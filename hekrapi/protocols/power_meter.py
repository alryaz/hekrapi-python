# -*- coding: utf-8 -*-
"""Basic protocol definition for a smart power meter"""
from enum import IntEnum
from typing import TYPE_CHECKING

from hekrapi.enums import FrameType
from hekrapi.protocol import Protocol, TO_STR, TO_FLOAT, TO_BOOL, TO_SIGNED_FLOAT, Command, Argument, Encoding, \
    register_supported_protocol

if TYPE_CHECKING:
    from hekrapi.device import DeviceInfo

__all__ = [
    "VoltageWarning",
    "CurrentWarning",
    "PowerSupplyWarning",
    "SwitchState",
    "PowerMeterProtocol"
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


@register_supported_protocol
class PowerMeterProtocol(Protocol):
    protocol_id = "power_meter"
    default_direct_port = 10000
    default_cloud_encoding_type = Encoding.RAW
    default_direct_encoding_type = Encoding.RAW

    @classmethod
    def _device_info_compatibility_checker(cls, device_info: 'DeviceInfo') -> bool:
        return device_info.product_name == 'Smart Meter'

    # Power meter commands
    query_device = Command(0, FrameType.SEND, response_command_id=1, description='Query device state in general')
    report_device = Command(1, FrameType.RECEIVE, arguments=[
        Argument("phase_count", int, 1, "type"),
        Argument("switch_state", TO_BOOL, 1, "sw"),
        Argument("total_energy_consumed", TO_FLOAT, 4, "total_Energy",
                 multiplier=0.01),
        Argument("warning_voltage", VoltageWarning, 1, "fault_Over_U"),
        Argument("total_active_power", TO_SIGNED_FLOAT, 3, "total_Active_power",
                 multiplier=0.0001),
        Argument("warning_current", CurrentWarning, 1, "fault_Over_I"),
        Argument("delay_timer", int, 2, "tmCd_M",
                 value_min=0, value_max=1440),
        Argument("delay_enabled", TO_BOOL, 1, "tmCdO_Sw"),
        Argument("warning_battery", PowerSupplyWarning, 1, "fault_SurplusDeficiency")
    ], description='Report device state')

    query_settings = Command(2, FrameType.SEND, response_command_id=8, description='Query device settings')
    report_settings = Command(8, FrameType.RECEIVE, arguments=[
        Argument("max_current", TO_FLOAT, 2, "top_I", multiplier=0.01,
                 value_min=0, value_max=120),
        Argument("max_voltage", int, 2, "top_U",
                 value_min=0, value_max=500),
        Argument("min_voltage", int, 2, "low_U",
                 value_min=0, value_max=500),
        Argument("option_electricity_purchase", TO_FLOAT, 4, "purchaseElectricity",
                 multiplier=0.01, value_min=0, value_max=999999.99),
        Argument("option_electricity_residual", TO_FLOAT, 4, "residualElectricity",
                 multiplier=0.01, value_min=0, value_max=999999.99),
        Argument("option_electricity_alarm", TO_FLOAT, 4, "electricityAlarm_set",
                 multiplier=0.01, value_min=0, value_max=999999.99),
        Argument("option_prepaid_enabled", TO_BOOL, 1, "prepaidFunctionSw")
    ], description='Report device settings')

    set_warning_limits = Command(3, FrameType.SEND, arguments=[
        Argument("max_current", TO_FLOAT, 2, "top_I",
                 multiplier=0.01, value_min=0, value_max=120),
        Argument("max_voltage", int, 2, "top_U",
                 value_min=0, value_max=500),
        Argument("min_voltage", int, 2, "low_U",
                 value_min=0, value_max=500),
    ], description='Set device limits for cut-off')

    reset = Command(5, FrameType.SEND, arguments=[
        Argument("active_energy_import", TO_FLOAT, 4, "import_Active_Energy",
                 multiplier=0.01, value_min=0, value_max=999999.99),
        Argument("active_energy_export", TO_FLOAT, 4, "export_Active_Energy",
                 multiplier=0.01, value_min=0, value_max=999999.99),
        Argument("total_energy_consumed", TO_FLOAT, 4, "total_Energy",
                 multiplier=0.01, value_min=0, value_max=999999.99),
    ])

    query_meter_id = Command(6, FrameType.SEND, response_command_id=7, description='Query meter serial number(s)')
    report_meter_id = Command(7, FrameType.RECEIVE, arguments=[
        Argument("meter_id_1", TO_STR, 1, "meterID1"),
        Argument("meter_id_2", TO_STR, 1, "meterID2"),
        Argument("meter_id_3", TO_STR, 1, "meterID3"),
        Argument("meter_id_4", TO_STR, 1, "meterID4"),
        Argument("meter_id_5", TO_STR, 1, "meterID5"),
        Argument("meter_id_6", TO_STR, 1, "meterID6"),
    ], description='Report meter serial number(s)')

    set_switch = Command(9, FrameType.SEND, arguments=[
        Argument("switch_state", SwitchState, 1, "sw")
    ], description='Set switch state')

    query_electricity = Command(10, FrameType.SEND, response_command_id=11,
                                description='Query device data regarding electricity')
    report_electricity = Command(11, FrameType.RECEIVE, arguments=[
        Argument("current_1", TO_FLOAT, 3, "I1",
                 multiplier=0.001, value_min=0, value_max=999.999,
                 description="Current on phase number 1"),
        Argument("current_2", TO_FLOAT, 3, "I2",
                 multiplier=0.001, value_min=0, value_max=999.999,
                 description="Current on phase number 2"),
        Argument("current_3", TO_FLOAT, 3, "I3",
                 multiplier=0.001, value_min=0, value_max=999.999,
                 description="Current on phase number 3"),
        Argument("voltage_1", TO_FLOAT, 2, "V1",
                 multiplier=0.1, value_min=0, value_max=999.9,
                 description="Voltage on phase number 1"),
        Argument("voltage_2", TO_FLOAT, 2, "V2",
                 multiplier=0.1, value_min=0, value_max=999.9,
                 description="Current on phase number 2"),
        Argument("voltage_3", TO_FLOAT, 2, "V3",
                 multiplier=0.1, value_min=0, value_max=999.9,
                 description="Current on phase number 3"),
        Argument("total_reactive_power", TO_SIGNED_FLOAT, 3, "total_Reactive_Power",
                 multiplier=0.0001, value_min=-99.9999, value_max=99.9999,
                 description="Total reactive power for all phases"),
        Argument("reactive_power_1", TO_SIGNED_FLOAT, 3, "reactive_Power1",
                 multiplier=0.0001, value_min=-99.9999, value_max=99.9999,
                 description="Reactive power on phase number 1"),
        Argument("reactive_power_2", TO_SIGNED_FLOAT, 3, "reactive_Power2",
                 multiplier=0.0001, value_min=-99.9999, value_max=99.9999,
                 description="Reactive power on phase number 2"),
        Argument("reactive_power_3", TO_SIGNED_FLOAT, 3, "reactive_Power3",
                 multiplier=0.0001, value_min=-99.9999, value_max=99.9999,
                 description="Reactive power on phase number 3"),
        Argument("total_active_power", TO_SIGNED_FLOAT, 3, "total_Active_Power",
                 multiplier=0.0001, value_min=-99.9999, value_max=99.9999,
                 description="Total active power for all phases"),
        Argument("active_power_1", TO_SIGNED_FLOAT, 3, "active_Power1",
                 multiplier=0.0001, value_min=-99.9999, value_max=99.9999,
                 description="Active power on phase number 1"),
        Argument("active_power_2", TO_SIGNED_FLOAT, 3, "active_Power2",
                 multiplier=0.0001, value_min=-99.9999, value_max=99.9999,
                 description="Active power on phase number 2"),
        Argument("active_power_3", TO_SIGNED_FLOAT, 3, "active_Power3",
                 multiplier=0.0001, value_min=-99.9999, value_max=99.9999,
                 description="Active power on phase number 3"),
        Argument("total_power_factor", TO_SIGNED_FLOAT, 2, "total_Constant",
                 multiplier=0.0001, value_min=-99.9999, value_max=99.9999),
        Argument("power_factor_1", TO_FLOAT, 2, "constant1",
                 multiplier=0.001, value_min=0, value_max=9.999,
                 description="Power factor on phase number 1"),
        Argument("power_factor_2", TO_FLOAT, 2, "constant2",
                 multiplier=0.001, value_min=0, value_max=9.999,
                 description="Power factor on phase number 2"),
        Argument("power_factor_3", TO_FLOAT, 2, "constant3",
                 multiplier=0.001, value_min=0, value_max=9.999,
                 description="Power factor on phase number 3"),
        Argument("current_frequency", TO_FLOAT, 2, "rate",
                 multiplier=0.01),
        # @TODO: min, max
        Argument("total_energy_consumed", TO_FLOAT, 4, "total_Energy",
                 multiplier=0.01),
        # @TODO: min, max
        Argument("active_energy_import", TO_FLOAT, 4, "import_Active_Energy",
                 multiplier=0.01),
        # @TODO: min, max
        Argument("active_energy_export", TO_FLOAT, 4, "export_Active_Energy",
                 multiplier=0.01),
    ], description='Report detailed device data')

    set_timer = Command(12, FrameType.SEND, arguments=[
        Argument("delay_timer", int, 2, "tmCd_M"),  # @TODO: min, max
        Argument("delay_enabled", TO_BOOL, 1, "tmCdO_Sw")
    ], description='Set shutdown timer')

    set_parameters = Command(13, FrameType.SEND, arguments=[
        # @TODO: description
        Argument("option_electricity_purchase", TO_FLOAT, 4, "purchaseElectricity",
                 multiplier=0.01, value_min=0, value_max=999999.99),
        # @TODO: description
        Argument("option_electricity_alarm", TO_FLOAT, 4, "electricityAlarm_set",
                 multiplier=0.01, value_min=0, value_max=999999.99),
        # @TODO: description
        Argument("option_prepaid_enabled", TO_BOOL, 1, "prepaidFunctionSw")
    ], description='Set parameters related to application')
