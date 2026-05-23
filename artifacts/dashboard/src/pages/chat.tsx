import React from "react";
import Layout from "../components/layout";
import { useListChatSessions, useCreateChatSession, useListChatMessages, getListChatMessagesQueryKey } from "@workspace/api-client-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { MessageSquarePlus, Send, User, Bot, Loader2 } from "lucide-react";
import { format } from "date-fns";
import { Link } from "wouter";
import { Badge } from "@/components/ui/badge";

export default function Chat() {
  const { data: sessions, refetch: refetchSessions } = useListChatSessions();
  const createSession = useCreateChatSession();
  
  const [activeSessionId, setActiveSessionId] = React.useState<string | null>(null);
  const [input, setInput] = React.useState("");
  const [streamingMessage, setStreamingMessage] = React.useState("");
  const [isStreaming, setIsStreaming] = React.useState(false);
  const scrollRef = React.useRef<HTMLDivElement>(null);

  // Set first session active by default
  React.useEffect(() => {
    if (sessions?.length && !activeSessionId) {
      setActiveSessionId(sessions[0].id);
    }
  }, [sessions, activeSessionId]);

  const { data: history, refetch: refetchHistory } = useListChatMessages(activeSessionId || "", {
    query: { enabled: !!activeSessionId, queryKey: getListChatMessagesQueryKey(activeSessionId || "") }
  });

  const handleNewSession = async () => {
    const session = await createSession.mutateAsync({ data: { title: "New Session" } });
    await refetchSessions();
    setActiveSessionId(session.id);
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || !activeSessionId || isStreaming) return;

    const content = input;
    setInput("");
    setIsStreaming(true);
    setStreamingMessage("");

    try {
      const response = await fetch(`/api/chat/sessions/${activeSessionId}/messages`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "text/event-stream"
        },
        body: JSON.stringify({ content })
      });

      if (!response.ok) {
        const errText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errText.slice(0, 200)}`);
      }
      if (!response.body) throw new Error("No response body");
      const contentType = response.headers.get("content-type") || "";
      if (!contentType.includes("text/event-stream")) {
        throw new Error(`Expected text/event-stream, got ${contentType}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const frames = buffer.split("\n\n");
        buffer = frames.pop() || "";

        for (const frame of frames) {
          // SSE frame: may have `event: <type>` and one or more `data: <json>` lines
          const dataLines = frame
            .split("\n")
            .filter((l) => l.startsWith("data: "))
            .map((l) => l.slice(6));
          if (dataLines.length === 0) continue;
          const dataStr = dataLines.join("\n");
          try {
            const data = JSON.parse(dataStr);
            if (data.type === "agent_message_delta") {
              setStreamingMessage((prev) => prev + (data.delta ?? ""));
            } else if (data.type === "tool_call") {
              const name = data.tool ?? data.name ?? "tool";
              setStreamingMessage((prev) => prev + `\n_[called ${name}]_\n`);
            } else if (data.type === "agent_message_complete" || data.type === "done") {
              // assistant message persisted server-side; refetch picks it up
            }
          } catch (e) {
            console.error("SSE parse error", e, dataStr);
          }
        }
      }
    } finally {
      setIsStreaming(false);
      await refetchHistory();
    }
  };

  // Scroll to bottom on new message
  React.useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [history, streamingMessage]);

  const renderContent = (content: string) => {
    // Simple citation replacement for demo [F:id]
    const parts = content.split(/(\[F:[a-zA-Z0-9-]+\])/g);
    return parts.map((part, i) => {
      if (part.startsWith("[F:") && part.endsWith("]")) {
        const id = part.slice(3, -1);
        return (
          <Link key={i} href={`/findings/${id}`}>
            <Badge variant="outline" className="mx-1 cursor-pointer hover:bg-accent font-mono text-[10px]">
              {id.substring(0, 8)}
            </Badge>
          </Link>
        );
      }
      return <span key={i}>{part}</span>;
    });
  };

  return (
    <Layout>
      <div className="flex h-[calc(100vh-8rem)] gap-6">
        {/* Left rail */}
        <div className="w-64 flex flex-col gap-4">
          <Button onClick={handleNewSession} className="w-full justify-start" variant="outline">
            <MessageSquarePlus className="h-4 w-4 mr-2" />
            New Session
          </Button>
          
          <ScrollArea className="flex-1 rounded-md border bg-card">
            <div className="p-2 space-y-1">
              {sessions?.map(session => (
                <button
                  key={session.id}
                  onClick={() => setActiveSessionId(session.id)}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm truncate transition-colors ${
                    activeSessionId === session.id 
                      ? "bg-primary text-primary-foreground" 
                      : "hover:bg-accent text-muted-foreground"
                  }`}
                >
                  {session.title || "Untitled Session"}
                  <div className="text-[10px] opacity-70 mt-1 font-mono">
                    {format(new Date(session.created_at), "MMM d, HH:mm")}
                  </div>
                </button>
              ))}
              {sessions?.length === 0 && (
                <div className="p-4 text-center text-sm text-muted-foreground">
                  No sessions yet
                </div>
              )}
            </div>
          </ScrollArea>
        </div>

        {/* Main chat area */}
        <Card className="flex-1 flex flex-col overflow-hidden">
          <ScrollArea className="flex-1 p-4" ref={scrollRef}>
            {!activeSessionId ? (
              <div className="h-full flex items-center justify-center text-muted-foreground">
                Select or create a session to start chatting
              </div>
            ) : (
              <div className="space-y-6 pb-4">
                {history?.map(msg => (
                  <div key={msg.id} className={`flex gap-4 ${msg.role === "user" ? "flex-row-reverse" : ""}`}>
                    <div className={`h-8 w-8 rounded-full flex items-center justify-center shrink-0 ${
                      msg.role === "user" ? "bg-primary text-primary-foreground" : "bg-muted text-foreground"
                    }`}>
                      {msg.role === "user" ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4" />}
                    </div>
                    <div className={`flex flex-col gap-1 max-w-[80%] ${msg.role === "user" ? "items-end" : "items-start"}`}>
                      <div className="text-xs text-muted-foreground font-mono">
                        {msg.role === "user" ? "You" : "Agent"} • {format(new Date(msg.created_at), "HH:mm:ss")}
                      </div>
                      <div className={`px-4 py-3 rounded-xl text-sm ${
                        msg.role === "user" 
                          ? "bg-primary text-primary-foreground rounded-tr-none" 
                          : "bg-muted text-foreground rounded-tl-none"
                      }`}>
                        <div className="whitespace-pre-wrap leading-relaxed">
                          {renderContent(msg.content)}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
                
                {isStreaming && (
                  <div className="flex gap-4">
                    <div className="h-8 w-8 rounded-full flex items-center justify-center shrink-0 bg-muted text-foreground">
                      <Bot className="h-4 w-4" />
                    </div>
                    <div className="flex flex-col gap-1 max-w-[80%] items-start">
                      <div className="text-xs text-muted-foreground font-mono flex items-center gap-2">
                        Agent <Loader2 className="h-3 w-3 animate-spin" />
                      </div>
                      <div className="px-4 py-3 rounded-xl text-sm bg-muted text-foreground rounded-tl-none min-w-[100px]">
                        <div className="whitespace-pre-wrap leading-relaxed">
                          {renderContent(streamingMessage)}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </ScrollArea>

          <div className="p-4 border-t bg-card mt-auto">
            <form onSubmit={handleSend} className="relative">
              <Input 
                value={input}
                onChange={e => setInput(e.target.value)}
                placeholder="Ask about compliance findings, patterns, or specific logs..."
                className="pr-12 py-6 bg-background"
                disabled={!activeSessionId || isStreaming}
              />
              <Button 
                type="submit" 
                size="icon" 
                className="absolute right-1.5 top-1.5 h-9 w-9"
                disabled={!input.trim() || !activeSessionId || isStreaming}
              >
                <Send className="h-4 w-4" />
              </Button>
            </form>
          </div>
        </Card>
      </div>
    </Layout>
  );
}
