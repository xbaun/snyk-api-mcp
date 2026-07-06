export function encodePurl(purl: string): string {
  return encodeURIComponent(purl);
}

export function buildPurl(
  packageType: string,
  packageName: string,
  packageVersion: string,
): string {
  return `pkg:${packageType}/${packageName}@${packageVersion}`;
}

export function derivePurl(
  packageType: string,
  purl?: string,
  packageName?: string,
  packageVersion?: string,
) {
  if (purl) return purl;
  if (packageName && packageVersion) {
    return buildPurl(packageType, packageName, packageVersion);
  }
  return null;
}

export function requirePurlInput(
  packageType: string,
  purl?: string,
  packageName?: string,
  packageVersion?: string,
) {
  const resolvedPurl = derivePurl(
    packageType,
    purl,
    packageName,
    packageVersion,
  );

  if (resolvedPurl) return resolvedPurl;

  throw new Error(
    'Provide either purl or the combination packageType/packageName/packageVersion.',
  );
}
