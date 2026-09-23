# Copyright 2026 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""command line entry: python -m casbin.shadow model.conf policy.csv"""

import argparse
import sys

from .checker import ShadowChecker, UnsupportedError


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m casbin.shadow",
        description="offline shadowing checker for the casbin priority model",
    )
    parser.add_argument("model", help="path to the model .conf file")
    parser.add_argument("policy", help="path to the policy .csv file")
    args = parser.parse_args(argv)

    try:
        report = ShadowChecker(model_path=args.model, policy_path=args.policy).check()
    except UnsupportedError as exc:
        print("unsupported: %s" % exc)
        return 2

    exit_code = 0
    for rule_report in report.reports:
        label = ", ".join(rule_report.rule)
        if rule_report.shadowed:
            exit_code = 1
            covered = ", ".join("#%d" % i for i in rule_report.covered_by)
            print("SHADOWED  #%d  %s  (covered by: %s)" % (rule_report.index, label, covered))
        elif rule_report.overlaps:
            exit_code = 1
            print("OVERLAP   #%d  %s" % (rule_report.index, label))
            for overlap in rule_report.overlaps:
                witness = overlap.witness
                point = ", ".join(
                    str(witness[key]) for key in ("sub", "dom", "obj", "act") if key in witness
                )
                print(
                    "    earlier #%d decides (%s) at [%s] verified=%s"
                    % (
                        overlap.earlier_index,
                        ", ".join(overlap.earlier_rule),
                        point,
                        overlap.verified,
                    )
                )
        else:
            print("OK        #%d  %s" % (rule_report.index, label))
    if not report.policy_order_preserved:
        print("warning: policy order changed during analysis", file=sys.stderr)
        exit_code = 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
