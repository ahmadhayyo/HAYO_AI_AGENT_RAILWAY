import { router, publicProcedure } from "./trpc.js";
import { z } from "zod";
import { runAndroidScan } from "./pentest/androidEngine";

/**
 * Pentest Router
 * 
 * Handles requests for web, android, and wallet security scans.
 */
export const pentestRouter = router({
  scanAndroid: publicProcedure
    .input(z.object({
      sessionId: z.string(),
      trafficLogs: z.array(z.object({
        url: z.string(),
        method: z.string(),
        headers: z.record(z.string()),
        body: z.string().optional(),
        responseStatus: z.number().optional(),
        responseBody: z.string().optional()
      })).optional()
    }))
    .mutation(async ({ input }) => {
      return await runAndroidScan(input.sessionId, input.trafficLogs);
    }),
  
  // Placeholder for other scan types
  scanWeb: publicProcedure
    .input(z.object({ url: z.string() }))
    .mutation(async ({ input }) => {
      return { status: "success", message: "Web scan started for " + input.url };
    }),

  scanWallet: publicProcedure
    .input(z.object({ address: z.string() }))
    .mutation(async ({ input }) => {
      return { status: "success", message: "Wallet scan started for " + input.address };
    })
});

/**
 * Main App Router
 */
export const appRouter = router({
  pentest: pentestRouter,
  // Add other sub-routers here if needed
});

export type AppRouter = typeof appRouter;
