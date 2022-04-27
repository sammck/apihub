#
# Copyright (c) 2022 Samuel J. McKelvie
#
# MIT License - See LICENSE file accompanying this package.
#

"""Exceptions defined by this package"""

from typing import Optional

from .internal_types import JsonableDict

class ApiHubError(Exception):
  """Base class for all error exceptions defined by this package."""
  #pass
