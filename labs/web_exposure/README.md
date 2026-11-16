# Lab 9: Web Exposure

**Why it matters:** forgotten admin pages, backup folders, `.git/` directories, and debug configs are common ways web servers leak information. Checking your own servers for them is basic hygiene.

## Exercise

Run `python3 -m labs.web_exposure.check --demo` from the repository root. This starts a temporary practice server on `127.0.0.1` with synthetic files, sends one `HEAD` request for each of a short list of common paths, prints what responded, and then shuts the server down. Expect `.git/`, `robots.txt`, `config.json`, and `backup/` to be found, and `admin/` to return `403`.

To check a practice server that you run yourself, pass its URL:

```sh
python3 -m labs.web_exposure.check http://127.0.0.1:8000
```

The checker uses only the Python standard library. It accepts only `localhost` or loopback IP addresses and refuses remote hosts, credentials, query strings, and fragments. It does not follow redirects, ignores `HTTP(S)_PROXY` settings so requests stay on your machine, and uses a short timeout.

Read the results with care. A `403` is only an HTTP response; it does not prove that a resource exists. Some servers reject `HEAD` requests or return `200` for every path. This is not a vulnerability scanner or a substitute for an authorized assessment.

**Takeaway:** keep deployable artifacts out of web roots, block version-control and backup paths at the server, and assess only systems you own or are explicitly authorized to test. Do not modify the local-only safeguard.
