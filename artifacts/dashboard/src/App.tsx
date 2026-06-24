import { Switch, Route, Router as WouterRouter, useLocation } from "wouter";
import { QueryClient, QueryClientProvider, QueryCache } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/components/theme-provider";
import NotFound from "@/pages/not-found";
import { ApiError } from "@workspace/api-client-react";
import React from "react";

// Pages
import Login from "./pages/login";
import Findings from "./pages/findings";
import FindingDetail from "./pages/finding-detail";
import Chat from "./pages/chat";
import Ledger from "./pages/ledger";
import Remediation from "./pages/remediation";
import Admin from "./pages/admin";
import OidcCallback from "./pages/oidc-callback";

// A 401 normally means the session expired, so bounce to /login. The one
// exception is a *step-up*-required 401 (`step_up_required: true`): that is an
// expected, in-session challenge that individual flows (break-glass request,
// approve, revoke) catch locally to open their MFA step-up dialog. Redirecting
// to /login on those would unmount the dialog mid-flow and silently abort the
// action, so they must be left for the originating component to handle.
export function redirectOnAuthFailure(
  error: unknown,
  location: string,
  setLocation: (to: string) => void,
): void {
  if (!(error instanceof ApiError) || error.status !== 401) return;
  const data = error.data as { step_up_required?: boolean } | null;
  if (data?.step_up_required) return;
  if (location !== "/login") setLocation("/login");
}

function App() {
  const [location, setLocation] = useLocation();

  const [queryClient] = React.useState(
    () =>
      new QueryClient({
        queryCache: new QueryCache({
          onError: (error) => {
            redirectOnAuthFailure(error, location, setLocation);
          },
        }),
        defaultOptions: {
          mutations: {
            onError: (error) => {
              redirectOnAuthFailure(error, location, setLocation);
            },
          },
          queries: {
            retry: false,
          },
        },
      })
  );

  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
            <Switch>
              <Route path="/login" component={Login} />
              <Route path="/" component={Findings} />
              <Route path="/findings" component={Findings} />
              <Route path="/findings/:id" component={FindingDetail} />
              <Route path="/chat" component={Chat} />
              <Route path="/ledger" component={Ledger} />
              <Route path="/remediation" component={Remediation} />
              <Route path="/admin" component={Admin} />
              <Route path="/oidc-callback" component={OidcCallback} />
              <Route component={NotFound} />
            </Switch>
          </WouterRouter>
          <Toaster />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}

export default App;
