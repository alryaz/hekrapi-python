#!/usr/bin/env python3
from enum import IntEnum

from ..protocol import Protocol
from ..command import Command, FrameType
from ..argument import Argument

__all__ = [
    "VoltageWarning",
    "CurrentWarning",
    "PowerSupplyWarning",
    "SwitchState",
    "PROTOCOL"]


class VoltageWarning(IntEnum):
    OK = 0
    OVERVOLTAGE = 1
    UNDERVOLTAGE = 2


class CurrentWarning(IntEnum):
    OK = 0
    CRITICAL = 1


class PowerSupplyWarning(IntEnum):
    OK = 0
    INSUFFICIENT = 1


class SwitchState(IntEnum):
    ON = 0
    OFF = 1
    FAILURE = 2


to_float = (int, float)
to_bool = (int, bool)
to_str = (int, str)

PROTOCOL = Protocol(
    Command(
        1, "reportDev", FrameType.RECEIVE,
        Argument("phase_count", int, 1, "type"),
        Argument("switch_state", to_bool, 1, "sw"),
        Argument(
            "total_energy_consumed",
            to_float,
            4,
            "total_Energy",
            multiplier=0.01),
        Argument("warning_voltage", VoltageWarning, 1, "fault_Over_U"),
        Argument("current_energy_consumption", to_float, 3,
                 "total_Active_power", multiplier=0.0001),
        Argument("warning_current", CurrentWarning, 1, "fault_Over_I"),
        Argument("delay_timer", int, 2, "tmCd_M", min=0, max=1440),
        Argument("delay_enabled", to_bool, 1, "tmCdO_Sw"),
        Argument(
            "warning_battery",
            PowerSupplyWarning,
            1,
            "fault_SurplusDeficiency")
    ),
    Command(2, "querySet", FrameType.SEND),
    Command(
        3, "setLimit", FrameType.SEND,
        Argument(
            "max_current",
            to_float,
            2,
            "top_I",
            multiplier=0.01,
            min=0,
            max=120),
        Argument("max_voltage", int, 2, "top_U", min=0, max=500),
        Argument("min_voltage", int, 2, "low_U", min=0, max=500),
    ),
    # 4th command unknown
    Command(
        5, "clear", FrameType.SEND,
        Argument(
            "active_energy_import",
            to_float,
            4,
            "import_Active_Energy",
            multiplier=0.01,
            min=0,
            max=999999.99),
        Argument(
            "active_energy_export",
            to_float,
            4,
            "export_Active_Energy",
            multiplier=0.01,
            min=0,
            max=999999.99),
        Argument(
            "total_energy_consumed",
            to_float,
            4,
            "total_Energy",
            multiplier=0.01,
            min=0,
            max=999999.99),
    ),
    Command(6, "queryMeterID", FrameType.SEND),
    Command(
        7, "reportMeterID", FrameType.RECEIVE,
        Argument("meter_id_1", to_str, 1, "meterID1"),
        Argument("meter_id_2", to_str, 1, "meterID2"),
        Argument("meter_id_3", to_str, 1, "meterID3"),
        Argument("meter_id_4", to_str, 1, "meterID4"),
        Argument("meter_id_5", to_str, 1, "meterID5"),
        Argument("meter_id_6", to_str, 1, "meterID6"),
    ),
    Command(
        8, "reportSet", FrameType.RECEIVE,
        Argument(
            "max_current",
            to_float,
            2,
            "top_I",
            multiplier=0.01,
            min=0,
            max=120),
        Argument("max_voltage", int, 2, "top_U", min=0, max=500),
        Argument("min_voltage", int, 2, "low_U", min=0, max=500),
        Argument(
            "option_electricity_purchase",
            to_float,
            4,
            "purchaseElectricity",
            multiplier=0.01,
            min=0,
            max=999999.99),
        Argument(
            "option_electricity_residual",
            to_float,
            4,
            "residualElectricity",
            multiplier=0.01,
            min=0,
            max=999999.99),
        Argument(
            "option_electricity_alarm",
            to_float,
            4,
            "electricityAlarm_set",
            multiplier=0.01,
            min=0,
            max=999999.99),
        Argument("option_prepaid_enabled", to_bool, 1, "prepaidFunctionSw")
    ),
    Command(
        9, "setSw", FrameType.SEND,
        Argument("switch_state", SwitchState, "sw", 1)
    ),
    Command(10, "queryData", FrameType.SEND),
    Command(
        11, "reportData", FrameType.RECEIVE,
        Argument(
            "current_1",
            to_float,
            3,
            "I1",
            multiplier=0.001,
            min=0,
            max=999.999),
        Argument(
            "current_2",
            to_float,
            3,
            "I2",
            multiplier=0.001,
            min=0,
            max=999.999),
        Argument(
            "current_3",
            to_float,
            3,
            "I3",
            multiplier=0.001,
            min=0,
            max=999.999),
        Argument(
            "voltage_1",
            to_float,
            2,
            "I1",
            multiplier=0.1,
            min=0,
            max=999.9),
        Argument(
            "voltage_2",
            to_float,
            2,
            "I2",
            multiplier=0.1,
            min=0,
            max=999.9),
        Argument(
            "voltage_3",
            to_float,
            2,
            "I3",
            multiplier=0.1,
            min=0,
            max=999.9),
        # @TODO: next argument wtf description: When the parameter is greater than 1000000, a negative sign is displayed. Parameter = reported value-1000000 and then divided.
        Argument(
            "total_active_power",
            to_float,
            3,
            "total_Reactive_Power",
            multiplier=0.0001,
            min=0,
            max=199.9999),
        Argument(
            "active_power_1",
            to_float,
            3,
            "active_Power1",
            multiplier=0.0001,
            min=0,
            max=199.9999),
        Argument(
            "active_power_2",
            to_float,
            3,
            "active_Power2",
            multiplier=0.0001,
            min=0,
            max=199.9999),
        Argument(
            "active_power_3",
            to_float,
            3,
            "active_Power3",
            multiplier=0.0001,
            min=0,
            max=199.9999),
        Argument(
            "total_active_power",
            to_float,
            3,
            "total_Active_Power",
            multiplier=0.0001,
            min=0,
            max=199.9999),
        Argument(
            "active_power_1",
            to_float,
            3,
            "active_Power1",
            multiplier=0.0001,
            min=0,
            max=199.9999),
        Argument(
            "active_power_2",
            to_float,
            3,
            "active_Power2",
            multiplier=0.0001,
            min=0,
            max=199.9999),
        Argument(
            "active_power_3",
            to_float,
            3,
            "active_Power3",
            multiplier=0.0001,
            min=0,
            max=199.9999),
        Argument(
            "total_power_factor",
            to_float,
            2,
            "total_Constant",
            multiplier=0.0001,
            min=0,
            max=199.9999),
        Argument(
            "power_factor_1",
            to_float,
            2,
            "constant1",
            multiplier=0.001,
            min=0,
            max=9.999),
        Argument(
            "power_factor_2",
            to_float,
            2,
            "constant2",
            multiplier=0.001,
            min=0,
            max=9.999),
        Argument(
            "power_factor_3",
            to_float,
            2,
            "constant3",
            multiplier=0.001,
            min=0,
            max=9.999),
        Argument(
            "current_frequency",
            to_float,
            2,
            "rate",
            multiplier=0.01),
        # @TODO: min, max
        Argument(
            "total_energy_consumed",
            to_float,
            4,
            "total_Energy",
            multiplier=0.01),
        # @TODO: min, max
        Argument(
            "active_energy_import",
            to_float,
            4,
            "import_Active_Energy",
            multiplier=0.01),
        # @TODO: min, max
        Argument(
            "active_energy_export",
            to_float,
            4,
            "export_Active_Energy",
            multiplier=0.01),
        # @TODO: min, max
    ),
    Command(
        12, "setTmCmd", FrameType.SEND,
        Argument("delay_timer", int, 2, "tmCd_M"),  # @TODO: min, max
        Argument("delay_enabled", to_bool, 1, "tmCdO_Sw")
    ),
    Command(
        13, "SetParameter", FrameType.SEND,
        Argument(
            "option_electricity_purchase",
            to_float,
            4,
            "purchaseElectricity",
            multiplier=0.01,
            min=0,
            max=999999.99),
        Argument(
            "option_electricity_alarm",
            to_float,
            4,
            "electricityAlarm_set",
            multiplier=0.01,
            min=0,
            max=999999.99),
        Argument("option_prepaid_enabled", to_bool, 1, "prepaidFunctionSw")
    )
)
