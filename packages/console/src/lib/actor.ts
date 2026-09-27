import { useSession } from "../session/session.js";

/**
 * True when an audit actor is the signed-in operator, so the console can say
 * "you" instead of an opaque ID. The raw ID stays available as a title.
 */
export function useIsMe(): (actorId: string | null | undefined) => boolean {
  const { session } = useSession();
  const id = session?.operator.id;
  return (actorId) => Boolean(id && actorId === id);
}
