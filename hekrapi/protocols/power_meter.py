# -*- coding: utf-8 -*-
""" Basic protocol definition for a smart power meter """
from enum import IntEnum

from ..argument import Argument
from ..command import Command, FrameType
from ..protocol import Protocol, TO_STR, TO_FLOAT, TO_BOOL, TO_SIGNED_FLOAT

__all__ = [
    "VoltageWarning",
    "CurrentWarning",
    "PowerSupplyWarning",
    "SwitchState",
    "PROTOCOL"
]


class VoltageWarning(IntEnum):
    """ Voltage warning status """
    OK = 0
    OVERVOLTAGE = 1
    UNDERVOLTAGE = 2


class CurrentWarning(IntEnum):
    """ Current warning status """
    OK = 0
    CRITICAL = 1


class PowerSupplyWarning(IntEnum):
    """ Backup power supply warning status """
    OK = 0
    INSUFFICIENT = 1


class SwitchState(IntEnum):
    """ Current state of device """
    ON = 0
    OFF = 1
    FAILURE = 2


PROTOCOL = Protocol(
    Command(0, FrameType.SEND, "queryDev", response_command_id=1),
    Command(1, FrameType.RECEIVE, "reportDev", arguments=[
        Argument("phase_count", int, 1, "type"),
        Argument("switch_state", TO_BOOL, 1, "sw"),
        Argument("total_energy_consumed", TO_FLOAT, 4, "total_Energy", multiplier=0.01),
        Argument("warning_voltage", VoltageWarning, 1, "fault_Over_U"),
        Argument("current_energy_consumption", TO_SIGNED_FLOAT, 3, "total_Active_power", multiplier=0.0001),
        Argument("warning_current", CurrentWarning, 1, "fault_Over_I"),
        Argument("delay_timer", int, 2, "tmCd_M", value_min=0, value_max=1440),
        Argument("delay_enabled", TO_BOOL, 1, "tmCdO_Sw"),
        Argument("warning_battery", PowerSupplyWarning, 1, "fault_SurplusDeficiency")
    ]),
    Command(2, FrameType.SEND, "querySet", response_command_id=8),
    Command(3, FrameType.SEND, "setLimit", arguments=[
        Argument("max_current", TO_FLOAT, 2, "top_I", multiplier=0.01, value_min=0, value_max=120),
        Argument("max_voltage", int, 2, "top_U", value_min=0, value_max=500),
        Argument("min_voltage", int, 2, "low_U", value_min=0, value_max=500),
    ]),
    # 4th command unknown
    Command(5, FrameType.SEND, "clear", arguments=[
        Argument("active_energy_import", TO_FLOAT, 4, "import_Active_Energy", multiplier=0.01, value_min=0, value_max=999999.99),
        Argument("active_energy_export", TO_FLOAT, 4, "export_Active_Energy", multiplier=0.01, value_min=0, value_max=999999.99),
        Argument("total_energy_consumed", TO_FLOAT, 4, "total_Energy", multiplier=0.01, value_min=0, value_max=999999.99),
    ]),
    Command(6, FrameType.SEND, "queryMeterID", response_command_id=7),
    Command(7, FrameType.RECEIVE, "reportMeterID", arguments=[
        Argument("meter_id_1", TO_STR, 1, "meterID1"),
        Argument("meter_id_2", TO_STR, 1, "meterID2"),
        Argument("meter_id_3", TO_STR, 1, "meterID3"),
        Argument("meter_id_4", TO_STR, 1, "meterID4"),
        Argument("meter_id_5", TO_STR, 1, "meterID5"),
        Argument("meter_id_6", TO_STR, 1, "meterID6"),
    ]),
    Command(8, FrameType.RECEIVE, "reportSet", arguments=[
        Argument("max_current", TO_FLOAT, 2, "top_I", multiplier=0.01, value_min=0, value_max=120),
        Argument("max_voltage", int, 2, "top_U", value_min=0, value_max=500),
        Argument("min_voltage", int, 2, "low_U", value_min=0, value_max=500),
        Argument("option_electricity_purchase", TO_FLOAT, 4, "purchaseElectricity", multiplier=0.01, value_min=0, value_max=999999.99),
        Argument("option_electricity_residual", TO_FLOAT, 4, "residualElectricity", multiplier=0.01, value_min=0, value_max=999999.99),
        Argument("option_electricity_alarm", TO_FLOAT, 4, "electricityAlarm_set", multiplier=0.01, value_min=0, value_max=999999.99),
        Argument("option_prepaid_enabled", TO_BOOL, 1, "prepaidFunctionSw")
    ]),
    Command(9, FrameType.SEND, "setSw", arguments=[
        Argument("switch_state", SwitchState, 1, "sw")
    ]),
    Command(10, FrameType.SEND, "queryData", response_command_id=11),
    Command(11, FrameType.RECEIVE, "reportData", arguments=[
        Argument("current_1", TO_FLOAT, 3, "I1", multiplier=0.001, value_min=0, value_max=999.999),
        Argument("current_2", TO_FLOAT, 3, "I2", multiplier=0.001, value_min=0, value_max=999.999),
        Argument("current_3", TO_FLOAT, 3, "I3", multiplier=0.001, value_min=0, value_max=999.999),
        Argument("voltage_1", TO_FLOAT, 2, "I1", multiplier=0.1, value_min=0, value_max=999.9),
        Argument("voltage_2", TO_FLOAT, 2, "I2", multiplier=0.1, value_min=0, value_max=999.9),
        Argument("voltage_3", TO_FLOAT, 2, "I3", multiplier=0.1, value_min=0, value_max=999.9),
        Argument("total_reactive_power", TO_SIGNED_FLOAT, 3, "total_Reactive_Power", multiplier=0.0001, value_min=-99.9999, value_max=99.9999),
        Argument("reactive_power_1", TO_SIGNED_FLOAT, 3, "reactive_Power1", multiplier=0.0001, value_min=-99.9999, value_max=99.9999),
        Argument("reactive_power_2", TO_SIGNED_FLOAT, 3, "reactive_Power2", multiplier=0.0001, value_min=-99.9999, value_max=99.9999),
        Argument("reactive_power_3", TO_SIGNED_FLOAT, 3, "reactive_Power3", multiplier=0.0001, value_min=-99.9999, value_max=99.9999),
        Argument("total_active_power", TO_SIGNED_FLOAT, 3, "total_Active_Power", multiplier=0.0001, value_min=-99.9999, value_max=99.9999),
        Argument("active_power_1", TO_SIGNED_FLOAT, 3, "active_Power1", multiplier=0.0001, value_min=-99.9999, value_max=99.9999),
        Argument("active_power_2", TO_SIGNED_FLOAT, 3, "active_Power2", multiplier=0.0001, value_min=-99.9999, value_max=99.9999),
        Argument("active_power_3", TO_SIGNED_FLOAT, 3, "active_Power3", multiplier=0.0001, value_min=-99.9999, value_max=99.9999),
        Argument("total_power_factor", TO_SIGNED_FLOAT, 2, "total_Constant", multiplier=0.0001, value_min=-99.9999, value_max=99.9999),
        Argument("power_factor_1", TO_FLOAT, 2, "constant1", multiplier=0.001, value_min=0, value_max=9.999),
        Argument("power_factor_2", TO_FLOAT, 2, "constant2", multiplier=0.001, value_min=0, value_max=9.999),
        Argument("power_factor_3", TO_FLOAT, 2, "constant3", multiplier=0.001, value_min=0, value_max=9.999),
        Argument("current_frequency", TO_FLOAT, 2, "rate", multiplier=0.01),
        # @TODO: min, max
        Argument("total_energy_consumed", TO_FLOAT, 4, "total_Energy", multiplier=0.01),
        # @TODO: min, max
        Argument("active_energy_import", TO_FLOAT, 4, "import_Active_Energy", multiplier=0.01),
        # @TODO: min, max
        Argument("active_energy_export", TO_FLOAT, 4, "export_Active_Energy", multiplier=0.01),
    ]),
    Command(12, FrameType.SEND, "setTmCmd", arguments=[
        Argument("delay_timer", int, 2, "tmCd_M"),  # @TODO: min, max
        Argument("delay_enabled", TO_BOOL, 1, "tmCdO_Sw")
    ]),
    Command(13, FrameType.SEND, "SetParameter", arguments=[
        Argument("option_electricity_purchase", TO_FLOAT, 4, "purchaseElectricity", multiplier=0.01, value_min=0, value_max=999999.99),
        Argument("option_electricity_alarm", TO_FLOAT, 4, "electricityAlarm_set", multiplier=0.01, value_min=0, value_max=999999.99),
        Argument("option_prepaid_enabled", TO_BOOL, 1, "prepaidFunctionSw")
    ]),
    compatibility_checker=lambda d: d.product_name == 'Smart Meter'
)
