# from unittest.mock import MagicMock
# import scapy

# from uanalyser.preprocessing.operations import calculate_package_time_difference


# def test_calculate_package_time_difference():
#     # Create mock packets
#     packet = MagicMock(spec=scapy.Packet)
#     first_packet = MagicMock(spec=scapy.Packet)

#     # Set the time attributes of the mock packets
#     packet.time = 1.234567
#     first_packet.time = 0.123456

#     # Call the function under test
#     result = calculate_package_time_difference(packet, first_packet)

#     # Assert the result
#     assert result == '1.111111'def test_calculate_package_time_difference():
#     # Create mock packets
#     packet = MagicMock(spec=scapy.Packet)
#     first_packet = MagicMock(spec=scapy.Packet)

#     # Set the time attributes of the mock packets
#     packet.time = 1.234567
#     first_packet.time = 0.123456

#     # Call the function under test
#     result = calculate_package_time_difference(packet, first_packet)

#     # Assert the result
#     assert result == '1.111111'


# def test_calculate_package_time_difference_with_zero_time_difference():
#     # Create mock packets
#     packet = MagicMock(spec=scapy.Packet)
#     first_packet = MagicMock(spec=scapy.Packet)

#     # Set the time attributes of the mock packets
#     packet.time = 0.123456
#     first_packet.time = 0.123456

#     # Call the function under test
#     result = calculate_package_time_difference(packet, first_packet)

#     # Assert the result
#     assert result == '0.000000'


# def test_calculate_package_time_difference_with_negative_time_difference():
#     # Create mock packets
#     packet = MagicMock(spec=scapy.Packet)
#     first_packet = MagicMock(spec=scapy.Packet)

#     # Set the time attributes of the mock packets
#     packet.time = 0.123456
#     first_packet.time = 0.234567

#     # Call the function under test
#     result = calculate_package_time_difference(packet, first_packet)

#     # Assert the result
#     assert result == '-0.111111'
