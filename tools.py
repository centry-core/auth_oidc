#!/usr/bin/python3
# coding=utf-8

#   Copyright 2022 getcarrier.io
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Tools """

import uuid

import jwt  # pylint: disable=E0401


def generate_state_id(module):
    """ Make and sign state id """
    state_uuid = str(uuid.uuid4())
    return state_uuid, jwt.encode(
        {"uuid": state_uuid},
        module.context.app.secret_key,
        algorithm="HS512",
    )


def get_state_id(module, target_state):
    """ Verify and get state UUID """
    try:
        state_data = jwt.decode(
            target_state, module.context.app.secret_key, algorithms=["HS512"]
        )
    except:
        raise ValueError("Invalid state")
    #
    return state_data["uuid"]
