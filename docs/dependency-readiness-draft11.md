# HTTP dependency readiness, 2026-09-11

The candidate pins httpx2 and httpcore2 to 2.12.0 together. Starlette's TestClient uses httpx2; application httpx remains 0.28.1. Official metadata and the unfiltered audit are retained in the coordinated draft evidence. All 135 prior dependency pins were checked against the fresh environment; pip is additionally pinned, for 136 explicit installed non-editable package pins.

The six previous HTTP advisory entries no longer appear. Pytest 8.4.2 still reports PYSEC-2026-1845 (the service duplicates the same ID; count once). Upstream's current chia-puzzles-py 0.20.3 requires pytest>=8.3.3,<9, while the advisory fixes begin at 9.0.3. Protocol dev requirements also pin 8.4.2. Removing the API audit ignore makes this a failing gate. No dependency override, edited third-party metadata, or waiver closes it.

A supported upstream dependency combination or a separately reviewed maintained backport is required. The API dependency audit and release remain NO-GO. The protocol's separate historical requirements-test.lock is not represented by the API environment and must receive its own validation.

Primary sources: https://pypi.org/project/httpx2/2.12.0/ ; https://pypi.org/pypi/httpcore2/2.12.0/json ; https://pypi.org/pypi/chia-puzzles-py/0.20.3/json ; https://github.com/pydantic/httpx2/security/advisories/GHSA-8xx6-hgc6-gc2m
