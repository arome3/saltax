"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";
import { WagmiProvider } from "wagmi";
import { useState, type ReactNode } from "react";
import { wagmiConfig } from "@/lib/wagmi-config";
import { WebSocketProvider } from "@/lib/websocket";
import { Toaster } from "sonner";
import { TooltipProvider } from "@/components/ui/tooltip";

export function Providers({ children }: { children: ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 10_000,
            retry: 2,
            refetchOnWindowFocus: false,
          },
        },
      }),
  );

  return (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false}>
      <WagmiProvider config={wagmiConfig}>
        <QueryClientProvider client={queryClient}>
          <WebSocketProvider>
            <TooltipProvider delayDuration={300}>
              {children}
              <Toaster
                position="bottom-right"
                richColors
                closeButton
                duration={5000}
              />
            </TooltipProvider>
          </WebSocketProvider>
        </QueryClientProvider>
      </WagmiProvider>
    </ThemeProvider>
  );
}
