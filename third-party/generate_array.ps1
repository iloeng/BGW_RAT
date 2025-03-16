param (
    [string]$InputFile,
    [string]$OutputFile,
    [string]$ArrayName
)

# 调用 xxd 生成数组
$xxdOutput = & "$PSScriptRoot\xxd.exe" -i $InputFile

# 获取输入文件的默认名称（将路径中的特殊字符替换为下划线）
$defaultName = $InputFile -replace '[\\/.:]', '_'

# 检查是否需要替换
if ($xxdOutput -match $defaultName) {
    # 替换默认的数组名称
    $xxdOutput = $xxdOutput -replace $defaultName, $ArrayName

    # 将结果写入输出文件
    $xxdOutput | Out-File $OutputFile -Encoding UTF8

    # 输出成功信息
    Write-Host "Success: Array name has been replaced from '$defaultName' to '$ArrayName'."
} else {
    # 输出失败信息
    Write-Host "Error: Default array name '$defaultName' not found in xxd output."
}
