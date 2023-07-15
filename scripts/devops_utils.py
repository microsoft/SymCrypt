"""
Utility files for working with Azure DevOps.

Copyright (c) Microsoft Corporation. Licensed under the MIT license.
"""

import typing

def set_task_variable(name: str, value: typing.Any) -> None:
    """
    Sets an Azure DevOps task variable.

    name: The name of the variable to set.
    value: The value to set the variable to.
    """

    print(f"##vso[task.setvariable variable={name};isOutput=true]{value}")