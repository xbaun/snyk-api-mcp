import type { UserConfig } from '@commitlint/types';
import { RuleConfigSeverity } from '@commitlint/types';

const config: UserConfig = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'header-max-length': [RuleConfigSeverity.Error, 'always', 200],
    'body-max-line-length': [RuleConfigSeverity.Disabled, 'always', Infinity],
  },
};

export default config;
