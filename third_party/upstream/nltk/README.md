# NLTK Upstream Distribution Provenance

The crawler installs the unmodified `nltk-3.10.4-py3-none-any.whl` published in
the official [stable v3.10.4 release](https://github.com/nltk/nltk/releases/tag/v3.10.4).
Its version and original notices remain unchanged. The installation lock binds
the exact release URL and hash, preserving artifact identity when a package
index offers different wheel bytes under the same version number.

[The distribution record](3.10.4/distribution.json) binds the official asset
URL, filename, byte size, SHA-256, release tag and license. The wheel is retrieved
into the external development cache and verified before use; built packages
are not tracked in Git. It contains the original Apache-2.0 license
and authors; the [development notice](../../../docs/licenses/NLTK-3.10.4.txt)
is byte-identical to that license.

`tools/nltk_distribution.py` verifies the complete wheel, metadata and runtime
version before installation. It binds every installed Python source and the
VERSION file to the admitted wheel without importing the package. Additional,
missing or changed source, redirects, native modules and sourceless bytecode
fail admission. Runtime commands retain the source-only import boundary.

Installation uses the complete hash-locked dependency graph, the verified local
wheel as a normal pip candidate, and `pip check`. No dependency constraint,
installed code or package metadata is patched. Regression tests cover the
model-artifact sandbox and legitimate consumer behavior. Upstream path-security
tests and actual crawler extraction are qualified separately; successful
crawling alone does not establish a security fix.

The superseded candidate record, earlier commit archive and its original record remain immutable evidence
for the individually approved historical secret-scanner fixture. The history
review binds both that archive and its Git blob. They are not installation
inputs. The retired custom NLTK builder has been removed.
