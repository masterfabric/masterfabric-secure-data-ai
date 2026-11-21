# Contributing

This is a lab repository. Changes are welcome when they keep it runnable on a laptop and keep every
number in the README reproducible.

## Ground rules

- **Synthetic data only.** Never add real names, ID numbers, IBANs, phone numbers or e-mails, not even
  your own, and not in tests, issues or screenshots. Extend `sdai/synth.py` instead.
- **Measured numbers only.** If a change affects results, re-run the evaluation (`make eval`, and
  `make llm-up owasp llm-down` for the model tests), regenerate images (`make charts`), and commit the
  new `results/*.json` with them. Never edit a results file by hand.
- **Security changes need tests,** including the attacks you expect to miss. Keep failing cases in the
  attack sets rather than deleting them.
- No keys in git. The pseudonymisation and hash keys come from `SDAI_PSEUDO_KEY` / `SDAI_HASH_SALT`
  or are random per process.
- One logical change per commit, Conventional Commit subject, and a body that explains why.

## License of contributions

By contributing you agree that your contribution is licensed under the AGPL-3.0, as described in
[LICENSE](LICENSE) and [NOTICE](NOTICE).
