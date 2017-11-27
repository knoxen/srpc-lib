%%==============================================================================================
%%
%% Pre-established Relationship
%%
%%==============================================================================================
%%----------------------------------------------------------------------------------------------
%%
%% Srpc Id
%%
%%----------------------------------------------------------------------------------------------
-define(SRPC_ID, <<"06pctu4DsplX">>).

%%----------------------------------------------------------------------------------------------
%%
%% Client SRP Value
%%
%%----------------------------------------------------------------------------------------------
-define(SRPC_VERIFIER, <<16#4CC99E03C59204FDE270081CA1DE9B640AD8C57EDADE0C37ED87351605198D72C4A36A8C4F86874172134D7DEA6BEB1189F6815BE680125D83D3A904540DBF5FFF2DD0CB275EAA5EEA07746A7F78F323183AB688F534C1E4FA885D92A3B200D3169781215DDD26C4842FB6DC3AF8D1011C546392DEA796BC555CEEAD458C19EA6F0E09507E2CC2BAB92F74DA2139693A24ABD36217A5A0836D44800F84660F9C0EE92685078F15FCC757CA67BB1A9A0C12F363AF026A524D34C43971BD0B5927ADC9460B749A4481247EFC1F8D5ABFAEDF07114FB3831A561CB09F7C7E2436C4ED25637CB7C6AE47056A237831F045C422812492F57633871329B954AD218AD7:2048>>).

%%==============================================================================================
%%
%% Options
%%
%%==============================================================================================
%%----------------------------------------------------------------------------------------------
%%
%% Srpc Options Setting
%%
%%----------------------------------------------------------------------------------------------
-define(SRPC_OPTIONS, ?SRPC_PBKDF2_SHA256_G2048_AES_256_CBC_HMAC_SHA256).

