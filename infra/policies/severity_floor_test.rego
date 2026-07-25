package ztk.severity_floor_test

import data.ztk.severity_floor

# PCI = P1
test_pci_chd_floor_p1 if {
    severity_floor.floor == "P1" with input as {
        "data_classification": "CHD"
    }
}

test_pci_scope_floor_p1 if {
    severity_floor.floor == "P1" with input as {
        "pci_scope": true
    }
}

# Antifraude = P0
test_antifraude_floor_p0 if {
    severity_floor.floor == "P0" with input as {
        "domain": "antifraude"
    }
}

# LGPD = P1
test_lgpd_floor_p1 if {
    severity_floor.floor == "P1" with input as {
        "domain": "lgpd_sensivel"
    }
}

# Default = P4
test_default_floor_p4 if {
    severity_floor.floor == "P4" with input as {}
}

# Debate valido se >= piso
test_debate_valid_above_floor if {
    severity_floor.debate_result_valid with input as {
        "domain": "antifraude",
        "debate_severity": "P0"
    }
}

# Debate invalido se < piso
test_debate_invalid_below_floor if {
    not severity_floor.debate_result_valid with input as {
        "domain": "antifraude",
        "debate_severity": "P1"
    }
}
