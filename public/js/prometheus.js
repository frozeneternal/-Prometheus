export function canFetchSeries(dashboard) {
  return dashboard?.prometheus?.available === true;
}
