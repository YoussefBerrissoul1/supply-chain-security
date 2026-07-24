/**
 * Découpe un tableau en pages en répartissant les éléments de façon équilibrée,
 * pour éviter qu'une dernière page ne contienne qu'un seul élément perdu.
 *
 * Exemple : 9 éléments avec idealPerPage=4
 *  - découpage naïf   -> [4, 4, 1]  (dernière page presque vide)
 *  - découpage équilibré -> [3, 3, 3]
 */
export function balancedChunks<T>(items: T[], idealPerPage: number): T[][] {
  if (!items || items.length === 0) return [];

  const totalPages = Math.max(1, Math.ceil(items.length / idealPerPage));
  const perPage = Math.ceil(items.length / totalPages);

  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += perPage) {
    chunks.push(items.slice(i, i + perPage));
  }
  return chunks;
}
