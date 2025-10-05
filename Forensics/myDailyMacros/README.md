Challenge Description:

DEADFACE has gotten hold of the HR departments contact list and has been distributing it with a macro in it. There is a phrase the RE team would like for you to pull out of the macro.

Submit the flag as flag{some_text}

Solve:

So this solve came pretty easily once I figured a few things out. First, I knew the file was an Excel file with some extra macros, and that the flag would be in the code of the macros (written in VBA). Once I knew that, I did some searching and found a Python based tool called [Oletools](https://github.com/decalage2/oletools/tree/master), which can be installed with this command:

```sh
sudo -H pip install -U oletools[full]
```

Once it's installed we only have to utilize a couple of its tool options to find the flag. First, we can analyze the file with `oleid`, which gives us this output:

```sh
overllama@overllama$ oleid HR_List.xlsm
--------------------+--------------------+----------+--------------------------
Indicator           |Value               |Risk      |Description
--------------------+--------------------+----------+--------------------------
File format         |MS Excel 2007+      |info      |
                    |Macro-Enabled       |          |
                    |Workbook (.xlsm)    |          |
--------------------+--------------------+----------+--------------------------
Container format    |OpenXML             |info      |Container type
--------------------+--------------------+----------+--------------------------
Encrypted           |False               |none      |The file is not encrypted
--------------------+--------------------+----------+--------------------------
VBA Macros          |Yes                 |Medium    |This file contains VBA
                    |                    |          |macros. No suspicious
                    |                    |          |keyword was found. Use
                    |                    |          |olevba and mraptor for
                    |                    |          |more info.
--------------------+--------------------+----------+--------------------------
XLM Macros          |No                  |none      |This file does not contain
                    |                    |          |Excel 4/XLM macros.
--------------------+--------------------+----------+--------------------------
External            |0                   |none      |External relationships
Relationships       |                    |          |such as remote templates,
                    |                    |          |remote OLE objects, etc
--------------------+--------------------+----------+--------------------------
```

We can see our suspicions confirmed when me look at the VBA Macros section. All we have to do is run a second command to find the flag: `olevba`

```sh
overllama@overllama$ olevba HR_List.xlsm

-------------------------------------------------------------------------------
VBA MACRO Module1
in file: xl/vbaProject.bin - OLE stream: 'Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Sub Deadface()
function Invoke-RandomCode {
    $randomCodeList = @(
        {
            # Random code block 1
            Write-Host "Hello, World!"
            $randomNumber = Get-Random -Minimum 1 -Maximum 100
            Write-Host "Random number: $randomNumber"
        },
        {
            # Random code block 2
            # flag{youll_never_find_this_}
            $randomString = [char[]](65..90) | Get-Random -Count 5 | foreach { [char]$_ }
            Write-Host "Random string: $randomString"
        },
        {
            # Random code block 3
            $currentTime = Get-Date
            Write-Host "Current time: $currentTime"
        }
    )

    $randomIndex = Get-Random -Minimum 0 -Maximum $randomCodeList.Count
    $randomCodeBlock = $randomCodeList[$randomIndex]

    & $randomCodeBlock
}

Invoke -RandomCode

End Sub
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook
in file: xl/vbaProject.bin - OLE stream: 'ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Sheet1
in file: xl/vbaProject.bin - OLE stream: 'Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(empty macro)
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|Suspicious|Write               |May write to a file (if combined with Open)  |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

As you can see, the flag is `flag{youll_never_find_this_}`

[Additional Reading](https://intezer.com/blog/malware-analysis/analyze-malicious-microsoft-office-files/)