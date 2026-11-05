# Invalid references

[missing file](absent.md)
![missing image](absent.png)
[missing anchor](docs/target.md#absent)

```bash
python3 main.py scan https://example.invalid --not-a-vulix-option
```

Inline option typo: `python3 main.py scan URL --not-inline`.
