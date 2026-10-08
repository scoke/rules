// 按节点名称中的地区关键字添加国旗 Emoji。按顺序匹配，先命中者生效：
// 容易被包含的写法放在后面，例如「印度尼西亚」要先于「印度」判断。

// [中文或长名称(不区分大小写), 两位代码(区分大小写且需独立出现), emoji]
const REGIONS = [
  ['香港|深港|沪港|京港|港|Hong ?Kong', 'HK|HKG', '🇭🇰'],
  ['台湾|台灣|台北|台中|新北|彰化|台|Taiwan', 'TW|TWN', '🇹🇼'],
  ['澳门|澳門|Macau|Macao', 'MO', '🇲🇴'],
  ['日本|东京|東京|大阪|埼玉|名古屋|沪日|深日|川日|泉日|Japan|Tokyo|Osaka', 'JP|JPN', '🇯🇵'],
  ['新加坡|狮城|獅城|Singapore', 'SG|SGP', '🇸🇬'],
  ['韩国|韓國|首尔|首爾|春川|韩|韓|Korea|Seoul', 'KR|KOR', '🇰🇷'],
  [
    '美国|美國|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|拉斯维加斯|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|纽约|迈阿密|亚特兰大|美|United States|America|Los Angeles|San Jose|Seattle|Chicago|New York|Dallas',
    'US|USA',
    '🇺🇸',
  ],
  ['加拿大|蒙特利尔|温哥华|多伦多|Canada|Toronto|Vancouver|Montreal', 'CA|CAN', '🇨🇦'],
  ['英国|英國|伦敦|倫敦|United Kingdom|Britain|England|London', 'UK|GB|GBR', '🇬🇧'],
  ['德国|德國|法兰克福|柏林|Germany|Frankfurt|Berlin', 'DE|DEU', '🇩🇪'],
  ['法国|法國|巴黎|France|Paris', 'FR|FRA', '🇫🇷'],
  ['荷兰|荷蘭|阿姆斯特丹|Netherlands|Amsterdam', 'NL|NLD', '🇳🇱'],
  ['俄罗斯|俄羅斯|莫斯科|伯力|Russia|Moscow', 'RU|RUS', '🇷🇺'],
  ['印度尼西亚|印尼|雅加达|Indonesia|Jakarta', 'ID|IDN', '🇮🇩'],
  ['印度|孟买|India|Mumbai', 'IN|IND', '🇮🇳'],
  ['澳大利亚|澳洲|悉尼|墨尔本|Australia|Sydney|Melbourne', 'AU|AUS', '🇦🇺'],
  ['马来西亚|馬來西亞|吉隆坡|Malaysia', 'MY|MYS', '🇲🇾'],
  ['泰国|泰國|曼谷|Thailand|Bangkok', 'TH|THA', '🇹🇭'],
  ['越南|胡志明|河内|Vietnam', 'VN|VNM', '🇻🇳'],
  ['菲律宾|菲律賓|马尼拉|Philippines|Manila', 'PH|PHL', '🇵🇭'],
  ['土耳其|伊斯坦布尔|Turkey|Türkiye|Istanbul', 'TR|TUR', '🇹🇷'],
  ['阿根廷|Argentina', 'AR|ARG', '🇦🇷'],
  ['巴西|圣保罗|Brazil|Sao Paulo', 'BR|BRA', '🇧🇷'],
  ['意大利|米兰|Italy|Milan', 'IT|ITA', '🇮🇹'],
  ['西班牙|马德里|Spain|Madrid', 'ES|ESP', '🇪🇸'],
  ['瑞士|苏黎世|Switzerland|Zurich', 'CH|CHE', '🇨🇭'],
  ['瑞典|斯德哥尔摩|Sweden|Stockholm', 'SE|SWE', '🇸🇪'],
  ['爱尔兰|都柏林|Ireland|Dublin', 'IE|IRL', '🇮🇪'],
  ['波兰|华沙|Poland|Warsaw', 'PL|POL', '🇵🇱'],
  ['芬兰|赫尔辛基|Finland|Helsinki', 'FI|FIN', '🇫🇮'],
  ['以色列|Israel', 'IL|ISR', '🇮🇱'],
  ['阿联酋|迪拜|United Arab Emirates|Dubai', 'AE|ARE|UAE', '🇦🇪'],
  ['南非|约翰内斯堡|South Africa|Johannesburg', 'ZA|ZAF', '🇿🇦'],
  ['中国|回国|中國|China', 'CN|CHN', '🇨🇳'],
  ['流量|到期|过期|剩余|套餐|官网|Traffic|Expire', '', '🏳️‍🌈'],
];

const COMPILED = REGIONS.map(([names, codes, emoji]) => ({
  names: new RegExp(names, 'i'),
  codes: codes ? new RegExp(`(?<![A-Za-z])(?:${codes})(?![A-Za-z])`) : null,
  emoji,
}));

// 名称开头的国旗、Emoji 及其后的空白
const LEADING_EMOJI =
  /^(?:\s*(?:[\u{1F1E6}-\u{1F1FF}]{2}|\p{Extended_Pictographic}\uFE0F?(?:\u200D\p{Extended_Pictographic}\uFE0F?)*))+\s*/u;

export function removeEmoji(name) {
  return name.replace(LEADING_EMOJI, '');
}

// customRules: [{ regex: RegExp, emoji }]，来自外部配置的 emoji= 行，存在时取代内置表。
export function addEmoji(name, customRules) {
  if (customRules?.length) {
    const hit = customRules.find((r) => r.regex.test(name));
    return hit ? `${hit.emoji} ${name}` : name;
  }
  const hit = COMPILED.find((r) => r.names.test(name) || r.codes?.test(name));
  return hit ? `${hit.emoji} ${name}` : name;
}
