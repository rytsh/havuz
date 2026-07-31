/**
 * Database marks.
 *
 * These used to come from `simple-icons`, which was a 3450-icon runtime
 * dependency serving five icons — and, more to the point, it does not have
 * Redshift, YugabyteDB or openGauss. Those three all fell back to the
 * PostgreSQL elephant, so three of eight cards in the catalog showed the wrong
 * database. An icon set that silently substitutes a different product's logo is
 * worse than one that admits it has no logo.
 *
 * So havuz keeps its own. The rules that make this cheap to maintain:
 *
 * **One path, one colour.** Every mark is a single `path` on a 24×24 grid,
 * tinted at render time with the `--brand` custom property (see
 * `.database-mark svg` in `app.css`). That is what lets a mark sit correctly on
 * both the light and the dark theme without a second asset. Multi-colour
 * official logos would need a file per theme and could not be tinted at all.
 *
 * **A missing mark is a generic mark, never someone else's.** `iconFor` falls
 * back to a plain database cylinder. A new profile added on the Rust side
 * therefore renders sensibly before anyone draws anything for it.
 *
 * Marks derived from brand artwork are simplified, single-colour
 * representations used to identify the product being connected to.
 */

export interface DatabaseIcon {
  /** Accessible name for the mark. */
  title: string;
  /** Brand colour, without the leading `#`. */
  hex: string;
  /** A single path on a 24×24 viewBox. */
  path: string;
}

/** The elephant, simplified to one path. */
const postgresql: DatabaseIcon = {
  title: "PostgreSQL",
  hex: "4169E1",
  path: "M17.128 0a10.134 10.134 0 0 0-2.755.403l-.063.02A10.922 10.922 0 0 0 12.6.258C11.422.238 10.41.524 9.594 1 8.79.721 7.122.24 5.364.336 4.14.403 2.804.775 1.814 1.82.827 2.865.305 4.482.415 6.682c.03.607.203 1.597.49 2.879.284 1.28.65 2.783 1.1 4.153.448 1.37.916 2.6 1.633 3.472.358.436.844.804 1.462.818.432.01.813-.163 1.148-.418.164.216.343.31.508.404.209.12.41.208.633.267.4.106 1.09.245 1.887.109.272-.046.56-.128.849-.25.01.3.022.596.033.889.038 1.001.06 1.914.35 2.7.046.13.174.79.684 1.36.51.572 1.51.941 2.648.702.803-.17 1.83-.477 2.516-1.478.678-.988.99-2.483 1.046-4.925.014-.114.03-.21.045-.3l.14.012h.017c.75.034 1.565-.075 2.246-.393.6-.28 1.05-.51 1.38-.95.081-.11.17-.24.19-.477.023-.237-.115-.62-.35-.807-.47-.375-.766-.24-1.085-.174a5.203 5.203 0 0 1-1.05.113c.965-1.632 1.656-3.366 2.052-4.905.234-.909.36-1.75.372-2.484.013-.734-.075-1.37-.399-1.913-1.011-1.69-2.665-2.174-3.964-2.29a8.63 8.63 0 0 0-.71-.031z",
};

/** The cockroach silhouette. */
const cockroachdb: DatabaseIcon = {
  title: "CockroachDB",
  hex: "6933FF",
  path: "M12 1.5c-2.34 0-4.53.6-6.44 1.66a11.9 11.9 0 0 0 2.02 6.6 12.03 12.03 0 0 0 4.42 4 12.03 12.03 0 0 0 4.42-4 11.9 11.9 0 0 0 2.02-6.6A13.19 13.19 0 0 0 12 1.5zM3.68 4.53A11.96 11.96 0 0 0 .5 12.6c0 1.6.31 3.12.88 4.51a9.53 9.53 0 0 0 5.2-2.36 9.4 9.4 0 0 0 2.6-4.2 13.6 13.6 0 0 1-5.5-6.02zm16.64 0a13.6 13.6 0 0 1-5.5 6.02 9.4 9.4 0 0 0 2.6 4.2 9.53 9.53 0 0 0 5.2 2.36c.57-1.39.88-2.9.88-4.51a11.96 11.96 0 0 0-3.18-8.07zM12 13.9a13.7 13.7 0 0 1-2.36 3.05A11.2 11.2 0 0 1 12 22.5a11.2 11.2 0 0 1 2.36-5.55A13.7 13.7 0 0 1 12 13.9z",
};

/** Redshift: the AWS data-warehouse cylinder with its arrow. */
const redshift: DatabaseIcon = {
  title: "Amazon Redshift",
  hex: "8C4FFF",
  path: "M12 1.2 3 3.6v12.9l9 2.4 9-2.4V3.6zm0 1.72 7.4 1.97v10.32L12 17.18zM6.9 7.05v6.6l1.6-.42V7.47zm3.3 1.2v4.44l1.6-.42V8.67zm3.3-2.1v7.8l1.6.42V6.57zM12 20.1l-3.3 1.5v1.2H15.3v-1.2z",
};

/** YugabyteDB: the stacked-ring mark. */
const yugabytedb: DatabaseIcon = {
  title: "YugabyteDB",
  hex: "FF6E42",
  path: "M12 1.5 2.4 7.05v9.9L12 22.5l9.6-5.55v-9.9zm0 2.08 7.8 4.5v2.05l-7.8-4.5-7.8 4.5V8.08zm0 4.24 7.8 4.5v2.05l-7.8-4.5-7.8 4.5v-2.05zm0 4.24 7.8 4.5-7.8 4.5-7.8-4.5z",
};

/** openGauss / GaussDB: the sail. */
const opengauss: DatabaseIcon = {
  title: "openGauss",
  hex: "0068B5",
  path: "M12 1.5C6.2 1.5 1.5 6.2 1.5 12S6.2 22.5 12 22.5 22.5 17.8 22.5 12 17.8 1.5 12 1.5zm0 2.1a8.4 8.4 0 0 1 8.4 8.4 8.4 8.4 0 0 1-8.4 8.4 8.4 8.4 0 0 1-8.4-8.4A8.4 8.4 0 0 1 12 3.6zm-.9 2.55v9.15l-3-3v3.36l4.8 4.8V8.31l3 3V7.95z",
};

const mysql: DatabaseIcon = {
  title: "MySQL",
  hex: "4479A1",
  path: "M16.405 5.501c-.115 0-.193.014-.274.033v.013h.014c.054.104.146.18.214.273.054.107.1.214.154.32l.014-.015c.094-.066.14-.172.14-.333-.04-.047-.046-.094-.08-.14-.04-.067-.126-.1-.18-.153zM5.77 18.695h-.927a50.854 50.854 0 0 0-.27-4.41h-.008l-1.41 4.41H2.45l-1.4-4.41h-.01a72.892 72.892 0 0 0-.195 4.41H0c.055-1.966.192-3.81.41-5.53h1.15l1.335 4.064h.008l1.347-4.064h1.1c.242 2.015.384 3.86.42 5.53zm4.017-4.08c-.378 2.045-.876 3.533-1.492 4.46-.482.716-1.01 1.073-1.583 1.073-.153 0-.34-.046-.566-.138v-.494c.11.017.24.026.386.026.268 0 .483-.075.647-.222.197-.18.295-.382.295-.605 0-.155-.077-.47-.23-.944L6.23 14.615h.91l.727 2.36c.164.536.233.91.205 1.123.4-1.064.678-2.227.837-3.483zm12.325 4.08h-2.63v-5.53h.885v4.85h1.745zm-3.32.135l-1.016-.5c.09-.075.177-.156.255-.25.433-.506.648-1.258.648-2.253 0-1.83-.718-2.746-2.155-2.746-.704 0-1.254.232-1.65.697-.43.508-.646 1.256-.646 2.245 0 .972.19 1.686.574 2.14.35.41.877.615 1.583.615.264 0 .506-.033.725-.098l1.325.772zm-1.9-.913c-.396 0-.685-.146-.87-.44-.184-.293-.276-.766-.276-1.416 0-1.136.345-1.705 1.037-1.705.396 0 .685.147.87.44.184.293.276.762.276 1.407 0 1.145-.345 1.714-1.037 1.714zm-3.87-3.302h-.887v3.19c0 .243-.056.42-.166.53-.11.11-.28.166-.51.166-.23 0-.4-.055-.51-.166-.11-.11-.166-.287-.166-.53v-3.19h-.886v3.257c0 .48.13.83.39 1.05.26.22.65.33 1.172.33.522 0 .912-.11 1.172-.33.26-.22.39-.57.39-1.05z",
};

const redis: DatabaseIcon = {
  title: "Redis",
  hex: "FF4438",
  path: "M12 2.4 1.2 6.6 12 10.8l10.8-4.2zm-10.8 6.3v1.8L12 14.7l10.8-4.2V8.7L12 12.9zm0 4.2v1.8L12 18.9l10.8-4.2v-1.8L12 17.1z",
};

/** The generic mark. Also what an unknown profile gets. */
const database: DatabaseIcon = {
  title: "Database",
  hex: "7C8DA6",
  path: "M12 2C7.6 2 4 3.34 4 5v14c0 1.66 3.6 3 8 3s8-1.34 8-3V5c0-1.66-3.6-3-8-3zm0 1.8c3.7 0 6.2 1.05 6.2 1.2S15.7 6.2 12 6.2 5.8 5.15 5.8 5 8.3 3.8 12 3.8zM5.8 7.62C7.24 8.3 9.48 8.7 12 8.7s4.76-.4 6.2-1.08v3.2c-.32.35-2.66 1.28-6.2 1.28s-5.88-.93-6.2-1.28zm0 5.5c1.44.68 3.68 1.08 6.2 1.08s4.76-.4 6.2-1.08v3.2c-.32.35-2.66 1.28-6.2 1.28s-5.88-.93-6.2-1.28zm0 5.5c1.44.68 3.68 1.08 6.2 1.08s4.76-.4 6.2-1.08V19c0 .17-2.4 1.2-6.2 1.2S5.8 19.17 5.8 19z",
};

/** The Java coffee cup, for the JDBC bridge. */
const jdbc: DatabaseIcon = {
  title: "JDBC",
  hex: "E76F00",
  path: "M8.85 15.6s-.9.53.63.7c1.85.21 2.8.18 4.84-.2 0 0 .54.34 1.29.63-4.58 1.96-10.37-.11-6.76-1.13zM8.3 13.02s-1.01.75.52.9c1.98.2 3.55.22 6.25-.3 0 0 .37.38.96.59-5.54 1.62-11.71.13-7.73-1.19zM17.9 17.5s.67.55-.73.98c-2.67.8-11.1 1.05-13.44.03-.84-.36.74-.87 1.23-.98.52-.11.81-.09.81-.09-.93-.66-6.03 1.29-2.59 1.85 9.37 1.52 17.08-.68 14.72-1.79zM9.27 10.35s-4.27 1.01-1.51 1.38c1.16.16 3.48.12 5.64-.06 1.77-.15 3.54-.47 3.54-.47s-.62.27-1.07.57c-4.33 1.14-12.7.61-10.29-.55 2.04-.98 3.69-.87 3.69-.87zM15.6 13.98c4.4-2.29 2.37-4.49.95-4.19-.35.07-.5.14-.5.14s.13-.2.37-.29c2.75-.97 4.87 2.85-.91 4.46 0 0 .07-.06.09-.12zM13.36 0s2.44 2.44-2.31 6.19c-3.81 3.01-.87 4.73 0 6.69-2.22-2-3.85-3.77-2.76-5.41C9.9 5.06 14.35 3.88 13.36 0zM9.7 21.9c4.22.27 10.7-.15 10.86-2.15 0 0-.3.76-3.49 1.37-3.6.68-8.04.6-10.67.17 0 0 .55.46 3.3.61z",
};

/**
 * Profile id to mark.
 *
 * Keyed by the `DriverProfile.id` the Rust registry serves, so adding a profile
 * on the server is the only place a name has to be spelled twice.
 */
const BY_PROFILE: Record<string, DatabaseIcon> = {
  postgres: postgresql,
  cockroachdb,
  redshift,
  yugabytedb,
  opengauss,
  mysql,
  redis,
  generic: jdbc,
};

/** Family id to mark, used when a profile has none of its own. */
const BY_FAMILY: Record<string, DatabaseIcon> = {
  postgres: postgresql,
  mysql,
  redis,
  jdbc,
};

/**
 * The mark for a profile.
 *
 * Never guesses: an id nobody has drawn gets the generic cylinder rather than
 * a neighbouring product's logo.
 */
export function iconFor(profileId: string, familyId?: string): DatabaseIcon {
  const key = profileId.toLowerCase().replace(/[\s-]+/g, "_");
  if (BY_PROFILE[key]) return BY_PROFILE[key];
  if (familyId && BY_FAMILY[familyId.toLowerCase()]) return BY_FAMILY[familyId.toLowerCase()];
  return database;
}
