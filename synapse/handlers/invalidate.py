# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
# Copyright 2017 - 2018 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
from typing import TYPE_CHECKING, Any, Dict, Optional, Set

from twisted.python.failure import Failure

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import SynapseError
from synapse.api.filtering import Filter
from synapse.logging.context import run_in_background
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage.state import StateFilter
from synapse.streams.config import PaginationConfig
from synapse.types import Requester
from synapse.util.async_helpers import ReadWriteLock
from synapse.util.stringutils import random_string
from synapse.visibility import filter_events_for_client

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class InvalidateHandler:
    """Handles event invalidation requests.
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()



    async def invalidate_event(self, event_id: str) -> None:
        """Invalidate inmemory cache for the given event.

        Args:
            event_id: event to be invalidated
        """
        self.store._invalidate_get_event_cache(event_id)
