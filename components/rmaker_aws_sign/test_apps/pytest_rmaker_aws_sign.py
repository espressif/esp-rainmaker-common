# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

from pytest_embedded_idf.dut import IdfDut
from pytest_embedded_idf.utils import idf_parametrize

TARGETS = ['esp32', 'esp32s2', 'esp32s3', 'esp32c2', 'esp32c3', 'esp32c5', 'esp32c6', 'esp32h2',
           'esp32p4', 'linux']


def run_unity_group(dut: IdfDut, group: str):
    """Run one Unity test group from the menu"""
    dut.expect("Press ENTER to see the list of tests")
    dut.write('')
    dut.expect("Enter test for running")
    dut.write(f'[{group}]')
    res = dut.expect(r"(\d+) Tests (\d+) Failures \d+ Ignored")
    assert int(res.group(1)) > 0, f"no tests ran in [{group}]"
    assert int(res.group(2)) == 0, f"{res.group(2).decode()} failures in [{group}]"


@idf_parametrize('target', TARGETS, indirect=['target'])
def test_aws_sign_crypto(dut: IdfDut):
    """Test the AWS signing crypto port against the FIPS and RFC 4231 vectors"""
    run_unity_group(dut, "aws_sign_crypto")


@idf_parametrize('target', TARGETS, indirect=['target'])
def test_aws_sign_sigv4(dut: IdfDut):
    """Test the AWS SigV4 signer against the published test vectors"""
    run_unity_group(dut, "aws_sign_sigv4")


@idf_parametrize('target', TARGETS, indirect=['target'])
def test_aws_sign_json(dut: IdfDut):
    """Test the AWS signing JSON port conformance suite"""
    run_unity_group(dut, "aws_sign_json")


@idf_parametrize('target', TARGETS, indirect=['target'])
def test_aws_sign_creds(dut: IdfDut):
    """Test AWS credential response parsing and region parsing"""
    run_unity_group(dut, "aws_sign_creds")


@idf_parametrize('target', TARGETS, indirect=['target'])
def test_aws_sign_port(dut: IdfDut):
    """Test AWS signing port installation and validation"""
    run_unity_group(dut, "aws_sign_port")


@idf_parametrize('target', TARGETS, indirect=['target'])
def test_aws_sign_http(dut: IdfDut):
    """Test the AWS credential and signed-request layers over a stub HTTP port"""
    run_unity_group(dut, "aws_sign_http")
