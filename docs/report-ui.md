# Local HTML report view

The CLI can turn an existing JSON report into a searchable HTML file. From
v0.4.0, the logo is embedded too, so the file works fully offline. It does not
start a server or send the report to a remote service.

```sh
tunnelscope html probe.json --output probe.html
```

Open `probe.html` in a browser. Search filters visible rows; the raw JSON is
available in a collapsed section. The view supports probe, receiver,
correlation, bidirectional comparison and lab reports. It presents evidence
already in the JSON; it does not run a new measurement or infer a root cause.
The logo is embedded in the generated HTML. The HTML is a self-contained file:
the logo, report content, styles and search work without network access.

![TunnelScope HTML report view](images/report-ui.png)

The generated HTML contains the complete report, including addresses and any
other fields in its JSON. Sanitize the JSON before sharing the HTML. Report
values are HTML-escaped before rendering.
