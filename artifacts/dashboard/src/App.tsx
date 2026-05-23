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
import Admin from "./pages/admin";

function App() {
  const [location, setLocation] = useLocation();

  const [queryClient] = React.useState(
    () =>
      new QueryClient({
        queryCache: new QueryCache({
          onError: (error) => {
            if (error instanceof ApiError && error.status === 401) {
              if (location !== "/login") {
                setLocation("/login");
              }
            }
          },
        }),
        defaultOptions: {
          mutations: {
            onError: (error) => {
              if (error instanceof ApiError && error.status === 401) {
                if (location !== "/login") {
                  setLocation("/login");
                }
              }
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
              <Route path="/admin" component={Admin} />
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
