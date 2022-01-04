# misp-terms

This page presents some of the most well know terms used in MISP. Sources used to build the glossary are also described below.

----

|Term|Meaning|
|----|-------|
|Attribute|Information used to describe indicators of compromise (IoC) and contextual data of an event [1]. Can represent network indicators (e.g., IP, domain, url), system indicators (e.g., JSON value) or application/business indicators (e.g., username) [2].|
|Category|Describes the semantics of an attribute (i.e., what kind of data/action it represents) (e.g., `md5`, `email`, `url`) [1]|
|Event|Represents an occurrence. Can originate from an incident, alert, report, or threat actor analysis [1]. Composes a set of attributes and metadata to represent the occurence information, context and indicators (e.g., List of hashes from Mirai C2 tools.) [1, 2].|
|Galaxy|Aggregators of a large set of information about a specific topic [1, 2]. Describe and provide the known information about a topic (e.g., Galaxy of malware used to infect Android devices [3]). Also know as clusters.|
|Tag|String only metadata identifier used to classify an event [1]. Identifiers can be chosen arbitrarily, but normally are chosen based on the existing taxonimies identifiers to ensure consistency and machine interpretation. (e.g.,`TLP: White`).|
|Taxonomy|Set of common classification tags, used to classify and organize information. Taxonomy tags are known as machine tags and are composed of a namespace, predication and optionally a value/extra identifier.|

## References

[1] - MISP Standard, https://www.misp-standard.org/rfc/misp-standard-core.html#name-attribute, accessed: 04 Jan 2021.

[2] - MISP Glossary, https://www.circl.lu/doc/misp/GLOSSARY.html, accessed: 04 Jan 2021.

[3] - Android Malware Galaxy Cluster, https://github.com/MISP/misp-galaxy/blob/main/clusters/android.json, accessed: 04 Jan 2021.

[4] - MISP Taxonomies, https://github.com/MISP/misp-taxonomies, accessed: 04 Jan 2021.