import argparse
from enum import Flag


class FlagsEnumParseAction(argparse.Action):
    """
     Argparse action for handling Enums that are bitwise flags.
     """
    def __init__(self, **kwargs):
        # Pop off the type value
        enum_type = kwargs.pop("type", None)
        # Ensure a Flag subclass is provided
        if enum_type is None:
            raise ValueError("type must be assigned a Flag enum when using FlagsEnumParseAction")
        if not issubclass(enum_type, Flag):
            raise TypeError("type must be a subclass of Flag enum when using FlagsEnumParseAction")

        kwargs.setdefault("choices", tuple(e.name for e in enum_type))

        super(FlagsEnumParseAction, self).__init__(**kwargs)



        self._enum = enum_type
        default_value = kwargs.pop("default", None)
        if default_value is None:
            self._final_value = enum_type(0)
        else:
            self._final_value = default_value

    def __call__(self, parser, namespace, values, option_string=None):
        # Convert value back into an Enum
        # bitwise operation to to an OR every time this is called; this allows for the enum values to be combined.
        self._final_value = self._final_value | self._enum[values]
        setattr(namespace, self.dest, self._final_value)