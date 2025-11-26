# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

# This file is a placeholder until we add some proper tests.
# Without it, the ci.yml workflow fails because of no code coverage.
import pytest
import seclab_taskflows

class Test00:
    def test_nothing(self):
        assert True

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
