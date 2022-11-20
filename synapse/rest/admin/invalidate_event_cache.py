from typing import TYPE_CHECKING, Tuple

from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from synapse.http.site import SynapseRequest
from synapse.rest.admin import assert_requester_is_admin
from synapse.rest.admin._base import admin_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer


class InvalidateEventCacheServlet(RestServlet):
    """Servlet which will remove event from cache

    POST /_synapse/admin/v1/invalidate_event_cache
    {
        "event_id": "!event:id"
    }

    returns:

    {}
    """

    PATTERNS = admin_patterns("/invalidate_event_cache$")

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.invalidate_handler = hs.get_invalidate_handler()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, ("event_id",))

        await self.invalidate_handler.invalidate_event(body["event_id"])

        return 200, {}
