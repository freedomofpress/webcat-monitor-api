#!/bin/sh
# One-time Rekor v1 history export from the public BigQuery dataset to the archive HDD.
# Needs billing enabled on the GCP project. Dry-run figures from 2026-10-18:
#   Identities.Extensions 2.87 TB, SAN URIs+emails 0.52 TB, Issuer+NotBefore 0.42 TB, Entries 0.34 TB
#   Digests (signer key fingerprints) 0.48 TB, Artifacts table (attestation subjects) 0.01 TB
#   => ~4.5 TB scanned, ~28 USD at 6.25 USD/TB, plus ~25-30 USD egress for the Parquet download.
# FulcioExtensions (1.36 TB) is skipped: it is a decoded copy of OIDs already present raw in Extensions.
# Format is skipped: it is empty for every row.
set -eu
PROJECT=${PROJECT:-webcat-511408}
BUCKET=${BUCKET:-gs://$PROJECT-rekor-export}   # must be in the US multi-region, same as the dataset
DATASET=rekor_export

case ${1:-} in
query)
  bq --project_id="$PROJECT" mk -f --location=US --dataset --default_table_expiration=604800 "$DATASET" >/dev/null
  bq --project_id="$PROJECT" query --use_legacy_sql=false --location=US \
     --destination_table="$DATASET.v1_identities" --replace --maximum_bytes_billed=5000000000000 "
SELECT e.LogIndex, e.IntegratedTime, e.Kind, i.EntryUUID, i.Issuer, i.NotBefore,
       i.Extensions, i.SANExtensionURIs, i.SANExtensionEmailAddresses, i.Digests
FROM \`bigquery-public-data.rekor.Identities\` i
JOIN \`bigquery-public-data.rekor.Entries\` e USING (EntryUUID)"
  bq --project_id="$PROJECT" query --use_legacy_sql=false --location=US \
     --destination_table="$DATASET.v1_artifacts" --replace --maximum_bytes_billed=100000000000 "
SELECT a.EntryUUID, e.LogIndex, a.Digest, a.AttestationType, a.SubjectName
FROM \`bigquery-public-data.rekor.Artifacts\` a
JOIN \`bigquery-public-data.rekor.Entries\` e USING (EntryUUID)"
  ;;
extract)
  gcloud storage buckets create "$BUCKET" --project="$PROJECT" --location=US --uniform-bucket-level-access 2>/dev/null || true
  bq --project_id="$PROJECT" extract --location=US --destination_format=PARQUET --compression=SNAPPY \
     "$DATASET.v1_identities" "$BUCKET/v1_identities/part-*.parquet"
  bq --project_id="$PROJECT" extract --location=US --destination_format=PARQUET --compression=SNAPPY \
     "$DATASET.v1_artifacts" "$BUCKET/v1_artifacts/part-*.parquet"
  gcloud storage du -s "$BUCKET"
  ;;
download)  # run on the VM after `gcloud auth login --no-browser` there
  mkdir -p /srv/archive/rekor-v1/export
  gcloud storage rsync -r "$BUCKET/" /srv/archive/rekor-v1/export/
  ;;
cleanup)   # after the download is verified: stop paying for the bucket and the result table
  gcloud storage rm -r "$BUCKET"
  bq --project_id="$PROJECT" rm -r -f -d "$DATASET"
  ;;
*) echo "usage: $0 query|extract|download|cleanup"; exit 2 ;;
esac
