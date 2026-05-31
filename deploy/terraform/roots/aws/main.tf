# PHI-Audit AWS root.
#
# What this provisions:
#   - EKS cluster (control plane + managed node group) — minimal, BYO-VPC
#   - IRSA role for the api-server pod with Bedrock + Secrets Manager + CloudWatch Logs read
#   - Secrets Manager entries for SESSION_SECRET and NOTARIZATION_SECRET
#   - NOTARIZATION_SECRET encrypted with a KMS key in a SEPARATE AWS account
#     (threat_model §23.2 — non-negotiable; co-locating the key in the
#     production account defeats the second-half tamper-evidence claim)
#   - Postgres via the M9.2 modules/postgres module
#
# What this does NOT provision (bring your own):
#   - VPC + subnets + NAT (use terraform-aws-modules/vpc/aws)
#   - Route53 records, ACM certs (ingress-specific)
#   - RDS security group (must allow :5432 from the EKS node SG)
#   - The KMS keys themselves (created by your platform team; their ARNs
#     are passed in via `db_kms_key_id` + `notarization_kms_key_id`)
#
# Operator workflow:
#   1. `tofu init && tofu plan -var-file=terraform.tfvars`
#   2. Apply the outputs to deploy/helm/phi-audit/values-aws.yaml overrides:
#        - `serviceAccount.api.annotations["eks.amazonaws.com/role-arn"]`  ← irsa_role_arn
#        - `database.existingSecret`                                       ← database_secret_name
#        - external-secrets sync rules to pull notarization + session secrets

locals {
  tags_all = merge(var.tags, {
    "phi-audit:tenant" = var.tenant_id
    "phi-audit:root"   = "aws"
  })
}

# --- EKS cluster -----------------------------------------------------------

resource "aws_iam_role" "eks_cluster" {
  name = "${var.name_prefix}-eks-cluster"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.tags_all
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "this" {
  name     = "${var.name_prefix}-eks"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.eks_version

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  # OIDC issuer is implicitly created; we read it below via data source for IRSA.

  depends_on = [aws_iam_role_policy_attachment.eks_cluster_policy]
  tags       = local.tags_all
}

# --- Node group ------------------------------------------------------------

resource "aws_iam_role" "node" {
  name = "${var.name_prefix}-eks-node"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.tags_all
}

resource "aws_iam_role_policy_attachment" "node_worker" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "node_cni" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "node_ecr" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "default"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.private_subnet_ids
  instance_types  = var.node_instance_types

  scaling_config {
    desired_size = var.node_desired_size
    max_size     = var.node_desired_size + 3
    min_size     = 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_cni,
    aws_iam_role_policy_attachment.node_ecr,
  ]

  tags = local.tags_all
}

# --- OIDC provider + IRSA role for the api-server pod ----------------------

data "tls_certificate" "eks_oidc" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_oidc.certificates[0].sha1_fingerprint]
  tags            = local.tags_all
}

locals {
  oidc_issuer_host = replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")
}

data "aws_iam_policy_document" "irsa_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer_host}:sub"
      values   = ["system:serviceaccount:${var.k8s_namespace}:${var.k8s_service_account}"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "api_irsa" {
  name               = "${var.name_prefix}-api"
  assume_role_policy = data.aws_iam_policy_document.irsa_assume.json
  tags               = local.tags_all
}

# Bedrock InvokeModel — scoped to the region; tighten to specific model arns
# in production if your model menu is fixed.
data "aws_iam_policy_document" "api_inline" {
  statement {
    sid       = "BedrockInvoke"
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
    resources = ["arn:aws:bedrock:${var.region}::foundation-model/*"]
  }
  statement {
    sid       = "SecretsManagerRead"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [aws_secretsmanager_secret.session.arn, aws_secretsmanager_secret.notarization.arn, aws_secretsmanager_secret.database.arn]
  }
  statement {
    sid       = "CloudWatchLogsRead"
    effect    = "Allow"
    actions   = ["logs:FilterLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
    resources = ["arn:aws:logs:${var.region}:*:log-group:*"]
  }
  # Decrypt for the notarization KMS key explicitly — it's in a DIFFERENT
  # account, so Secrets Manager's default same-account decrypt grant does
  # not apply. The cross-account key policy on `notarization_kms_key_id`
  # must allow this role's arn under `kms:Decrypt` (set up out-of-band by
  # the notarization-account operator; see README).
  statement {
    sid       = "NotarizationKmsDecrypt"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [var.notarization_kms_key_id]
  }
}

resource "aws_iam_role_policy" "api_inline" {
  name   = "api-permissions"
  role   = aws_iam_role.api_irsa.id
  policy = data.aws_iam_policy_document.api_inline.json
}
