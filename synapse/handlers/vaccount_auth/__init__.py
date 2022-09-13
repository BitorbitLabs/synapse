"""Top-level module `Vaccount` auth Provider for `synapse`.
This module provider login/registration based on signature by private key associated
with `Vaccount` stored on `VelasChain` or ephemeral.
"""

__version__ = "0.1.0"
__version_info__ = tuple(
    int(i) for i in __version__.split(".") if i.isdigit()
)

from synapse.handlers.vaccount_auth.auth_provider import VaccountAuthProvider
