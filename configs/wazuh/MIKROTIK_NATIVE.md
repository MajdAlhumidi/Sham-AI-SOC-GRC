# Native MikroTik authentication logs

These additive files cover the observed RouterOS remote-log format without a
Syslog `program_name`:

```text
system,error,critical MOKROTIK-STAR: login failure for user admin from 192.168.100.254 via winbox
```

`mikrotik_native_decoder.xml` extracts `dstuser`, `srcip`, and `protocol`.
The router identity is deliberately limited to `MOKROTIK-STAR`; adapt and test
the prematch before using another identity.

`mikrotik_native_rules.xml` uses IDs 100110–100112, independently of the existing
100100–100106 rules. A single matching failure triggers 100111 at level 7.
Repeated failures from the same source within 120 seconds can trigger 100112
at level 10. This is detection evidence, not proof of a malicious actor.

Install the decoder under `/var/ossec/etc/decoders/sham_mikrotik_native.xml` and
the rules under `/var/ossec/etc/rules/sham_mikrotik_native.xml`. Back up the
current configuration, verify the IDs are unused, run `wazuh-analysisd -t`,
and test the actual log using:

```sh
sudo /var/ossec/bin/wazuh-logtest -U 100111:7:sham-mikrotik-native-auth -l 10.8.0.2
```

Restart `wazuh-manager` after validation. Keep the existing global alert level
and the Agent ingestion threshold unchanged. A fresh login attempt is needed
for an end-to-end test; `wazuh-logtest` does not create a production incident.

Validation on Wazuh 4.14.6 covered the observed failure, repeated failures,
ordinary subscriber authentication, Python log copies, and another router
identity. Ordinary subscriber logs did not trigger this rule; Python copies
and another identity remained outside this decoder.

These files do not replace `custom_rules.xml` or other existing deployment
rules, and do not execute containment or create a case in TheHive.
