export function requestLogSummary(request: {
  method: string;
  routeOptions?: { url?: string };
}): { method: string; route: string } {
  return {
    method: request.method,
    route: request.routeOptions?.url ?? "unresolved"
  };
}
