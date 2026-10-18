#!/bin/sh
# One-time Rekor v1 history export from the public BigQuery dataset to the archive HDD.
# Needs billing enabled on the GCP project.
#
# Lessons from the first attempt (2026-10-18):
# - Entries LEFT JOIN Identities, never an inner join: ~92M entries (2.8%) have no identity row and the
#   tree check needs every leaf.
# - The loader's SANExtensionURIs/EmailAddresses are empty for ~0.9% of Fulcio certs although the raw
#   SAN holds a URI or email. Keep the raw 2.5.29.17 for those rows and parse it locally.
# - Snappy Parquet of base64 extension values was 1.4 TB. Decoding to bytes, dropping the SCT and key
#   identifiers, clustering by LogIndex and extracting with ZSTD gives ~70 B/row, about 230 GB.
# - FulcioExtensions is a decoded copy of OIDs already in Extensions; Format is empty for every row.
# Dry run of the query below: 3.98 TB, ~25 USD. Egress of the Parquet: ~0.12 USD/GB.
set -eu
PROJECT=${PROJECT:-webcat-511408}
BUCKET=${BUCKET:-gs://$PROJECT-rekor-export}   # must be in the US multi-region, same as the dataset
DATASET=rekor_export

EXPORT_SQL='
SELECT e.LogIndex, e.IntegratedTime, e.Kind,
       COALESCE(SAFE.FROM_HEX(e.EntryUUID), CAST(e.EntryUUID AS BYTES)) AS EntryUUID,
       i.IdentityGoType, i.ID, i.Issuer, i.NotBefore,
       ARRAY(SELECT AS STRUCT x.Key, COALESCE(SAFE.FROM_BASE64(x.Value), CAST(x.Value AS BYTES)) AS Value, x.Critical
             FROM UNNEST(i.Extensions) x
             WHERE x.Key NOT IN ("1.3.6.1.4.1.11129.2.4.2","2.5.29.14","2.5.29.35","2.5.29.15","2.5.29.37","2.5.29.19")
               AND (x.Key <> "2.5.29.17" OR (ARRAY_LENGTH(i.SANExtensionURIs) = 0 AND ARRAY_LENGTH(i.SANExtensionEmailAddresses) = 0))) AS Extensions,
       i.SANExtensionURIs, i.SANExtensionEmailAddresses,
       IF(i.Issuer LIKE "%sigstore.dev%", [], i.Digests) AS Digests,
       i.PGPIdentities
FROM `bigquery-public-data.rekor.Entries` e
LEFT JOIN `bigquery-public-data.rekor.Identities` i USING (EntryUUID)'

case ${1:-} in
query)
  bq --project_id="$PROJECT" mk -f --location=US --dataset "$DATASET" >/dev/null
  JOB=$(bq --project_id="$PROJECT" query --use_legacy_sql=false --location=US --nosync --format=none \
     --destination_table="$DATASET.v1" --replace --clustering_fields=LogIndex --maximum_bytes_billed=4500000000000 "$EXPORT_SQL" | grep -o 'bqjob_[a-z0-9_]*')
  echo "export job $JOB"; bq --project_id="$PROJECT" wait "$JOB" >/dev/null; bq --project_id="$PROJECT" show -j "$JOB" | tail -3
  bq --project_id="$PROJECT" query --use_legacy_sql=false --location=US --format=none \
     --destination_table="$DATASET.v1_artifacts" --replace --maximum_bytes_billed=100000000000 "
SELECT EntryUUID, Digest, AttestationType, SubjectName
FROM \`bigquery-public-data.rekor.Artifacts\`"   # LogIndex is attached locally via EntryUUID
  ;;
extract)
  gcloud storage buckets create "$BUCKET" --project="$PROJECT" --location=US --uniform-bucket-level-access 2>/dev/null || true
  bq --project_id="$PROJECT" extract --location=US --destination_format=PARQUET --compression=ZSTD \
     "$DATASET.v1" "$BUCKET/v1/part-*.parquet"
  bq --project_id="$PROJECT" extract --location=US --destination_format=PARQUET --compression=ZSTD \
     "$DATASET.v1_artifacts" "$BUCKET/v1_artifacts/part-*.parquet"
  gcloud storage du -s "$BUCKET"
  ;;
download)  # run on the VM after `gcloud auth login --no-browser` there
  mkdir -p /srv/archive/rekor-v1/export
  gcloud storage rsync -r "$BUCKET/" /srv/archive/rekor-v1/export/
  ;;
verify)    # on the VM: every object present with the same size, then row counts per file are readable
  gcloud storage ls -l -r "$BUCKET/**" | grep parquet | awk '{print $1, $3}' | sed "s|$BUCKET/||" | sort > /tmp/remote.txt
  (cd /srv/archive/rekor-v1/export && find . -name '*.parquet' -printf '%s %P\n' | sort) > /tmp/local.txt
  awk '{print $1, $2}' /tmp/remote.txt | sort > /tmp/r2.txt; diff /tmp/r2.txt /tmp/local.txt && echo "all objects match"
  ;;
cleanup)   # after the download is verified: stop paying for the bucket and the result table
  gcloud storage rm -r "$BUCKET"
  bq --project_id="$PROJECT" rm -r -f -d "$DATASET"
  ;;
*) echo "usage: $0 query|extract|download|verify|cleanup"; exit 2 ;;
esac
