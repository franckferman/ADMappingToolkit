@{
    ExcludeRules = @(
        # Interactive CLI scripts — Write-Host with -ForegroundColor is intentional
        'PSAvoidUsingWriteHost',

        # UTF-8 without BOM is intentional for cross-platform compatibility
        'PSUseBOMForUnicodeEncodedFile',

        # Network scanning code — empty catch blocks intentionally swallow connection failures
        'PSAvoidUsingEmptyCatchBlock',

        # Dead variables in original code left for forward-compatibility
        'PSUseDeclaredVarsMoreThanAssignments'
    )
}
