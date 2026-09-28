# Fetch upstream source trees used by the family lanes.  The source lock
# under src/config/source_locks/ pins the exact commit/archive hash each lane
# requires; `latest`/branch checkouts are never used as pins.
git clone https://github.com/PQClean/PQClean.git
git clone https://github.com/open-quantum-safe/liboqs.git

# SNOVA round-2 reference (the pqclab-snova/SNOVA HEAD is round 3; the lane
# stays on the round-2 commit that matches plans/specs/snova-round2-spec.pdf).
git clone https://github.com/PQCLAB-SNOVA/SNOVA.git
git -C SNOVA checkout 13182903755ade177e02d1fea77f0bd2e1e1a280
mkdir -p SNOVA/reference
cp -r SNOVA/src/* SNOVA/reference/
rm -rf SNOVA/reference/test SNOVA/reference/test_speed SNOVA/reference/build_libo SNOVA/reference/wasmapi.*
cp SNOVA/LICENSE SNOVA/reference/LICENSE

# Official SNOVA round-2 KAT responses, used to regenerate
# tests/fixtures/snova/kat_reference.json with
# scripts/generate_snova_fixtures.py --kat-root projects/SNOVA_KAT.
git clone https://github.com/PQCLAB-SNOVA/SNOVA_KAT.git
git -C SNOVA_KAT checkout a1bf39dc59c14a3348c27d66aa5197fc22041a56
