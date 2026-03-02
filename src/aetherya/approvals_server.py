from __future__ import annotations

import aetherya.api_server as api_server


def main(argv: list[str] | None = None) -> int:
    base_args = ["--service-mode", "approvals", "--port", "8081"]
    if argv:
        base_args.extend(argv)
    return api_server.main(base_args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
