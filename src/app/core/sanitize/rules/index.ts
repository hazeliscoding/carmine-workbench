import { Rule } from '../types';
import { authorizationHeaders } from './authorization-headers/rule';
import { cookies } from './cookies/rule';
import { jwt } from './jwt/rule';
import { privateKeys } from './private-keys/rule';
import { sensitiveKeys } from './sensitive-keys/rule';
import { urlParams } from './url-params/rule';

// Order breaks ties between context findings on the same span: the more specific name wins.
export const RULES: readonly Rule[] = [jwt, privateKeys, authorizationHeaders, cookies, urlParams, sensitiveKeys];
