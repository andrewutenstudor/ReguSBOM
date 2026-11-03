/**
 * ReguBOM — Edition Configuration & Feature Flags.
 * Clean abstraction separating Community Edition (Open Source, GNU AGPLv3)
 * from Enterprise Edition (Commercial Add-on).
 */

const editionRaw = (
  import.meta.env.VITE_EDITION ||
  import.meta.env.VITE_REGUBOM_EDITION ||
  ''
).toLowerCase().trim();

export const isEE = editionRaw === 'ee' || editionRaw === 'enterprise';

export const EDITION_CONFIG = {
  isEE,
  edition: isEE ? 'enterprise' : 'community',
  name: isEE ? 'ReguBOM Enterprise Edition' : 'ReguBOM Community Edition',
  shortName: isEE ? 'ReguBOM EE' : 'ReguBOM CE',
  version: isEE ? 'v2.0.0 (Enterprise Sovereign)' : 'v2.0.0-ce (GNU AGPLv3)',
  badge: isEE ? 'Enterprise Sovereign' : 'Open Source (AGPLv3)',
  licenseText: isEE ? 'Air-Gapped Sovereign Commercial License' : 'GNU Affero General Public License v3.0 (AGPLv3)',
  features: {
    auth: isEE,
    catalog: isEE,
    drift: isEE,
    pdfDossier: isEE,
    assetCatalog: isEE,
    diffDrift: isEE,
    acnModule: isEE,
    enterpriseAuth: isEE,
    mfaTotp: isEE,
    scopedApiKeys: isEE,
    auditLogsExport: isEE,
    licenseManagement: isEE,
  },
};

export default EDITION_CONFIG;
