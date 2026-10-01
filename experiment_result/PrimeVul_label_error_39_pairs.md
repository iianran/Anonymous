# PrimeVul Test-Set Label Errors, 39 Pairs: Evidence Archive

## 1. Master List

| # | Pair (V/S) | Project | CVE | Erroneous side | Evidence class | Evidence highlights |
|---|---|---|---|---|---|---|
| 1 | 195752/232405 | tensorflow | CVE-2021-37647 | S side | A (commit) | 965b97e4a+000e37b4b completed the validation; self-admitted "Existing validation was incomplete" |
| 2 | 198116/269323 | tensorflow | CVE-2021-37635 | S side | A (commit) | 6d3238fc9 integer overflow + negative value check |
| 3 | 195073/221123 | tensorflow | CVE-2022-23584 | S side | A (commit) | ab51e5b decode_image_op leak-prevention guard; purely new addition, absent from S |
| 4 | 195404/225563 | tensorflow | CVE-2022-21735 | S side | A (commit) | 216525144ee7+ee50d1e00f81 pooling_ratio lower-bound guard |
| 5 | 210904/442815 | curl | CVE-2018-16842 | S side | A (commit) | d530e92f59ae is the exact fix (len -= cut -> cut+1 verbatim) |
| 6 | 212834/462409 | rsyslog | CVE-2018-16881 | S side | A (commit) | 89955b0bc one commit sweeping three modules |
| 7 | 210271/432093 | vim | CVE-2022-2923 | S side | A (commit) | a80874d9b84a two else -> else if(depth<MAXWLEN-1) guards, zero presence in S |
| 8 | 195909/234875 | ImageMagick | CVE-2017-13139 | S side | A (commit) | master png.c L5357 line-level hit (Category III) |
| 9 | 215038/482692 | gst-plugins-good | CVE-2016-9810 | S side | A (commit) | 153a8ae flxdec rewrite |
| 10 | 210702/439500 | squashfs-tools | CVE-2021-40153 | S side | A (commit) | 2bf96e1ec unsquash-4.c (verified against the true mate) |
| 11 | 210700/439495 | squashfs-tools | CVE-2021-40153 | S side | A (commit) | 2bf96e1ec (same commit, already verified) |
| 12 | 210701/439495 | squashfs-tools | CVE-2021-40153 | S side | A (commit) | 2bf96e1ec (also a pairing failure; see separate archive) |
| 13 | 211700/450830 | linux | CVE-2022-26490 | S side | A (commit) | 77e5fe8f17+f2e19b3659+996419e059 nfc st21nfca |
| 14 | 212083/454759 | linux | CVE-2022-3077 | S side | A (commit) | 39244cc75482 i2c-ismt; the commit embeds a KASAN log |
| 15 | 202719/337848 | linux | CVE-2022-0322 | S side | A (commit) | 18ae07691d43 commit message explicitly names the __u16 overflow |
| 16 | 197824/264657 | gpac | CVE-2022-1795 | S side | A (commit) | bf35245e (same-day c535bad5 reverted a typo) |
| 17 | 202688/336807 | ghostpdl | CVE-2020-16287 | S side | A (commit) | 234110d58955+4763e7f89953 gdevlprn.g |
| 18 | 198927/285157 | radare2 | CVE-2022-1297 | S side | A (commit) | 48f0ea79f ne.c guard added on the callee (V calls it at line 8) |
| 19 | 207780/401034 | radare2 | CVE-2022-1244 | S side | A (commit) | master bin_dyldcache.c guard verbatim present (Category III) |
| 20 | 201872/325821 | gnutls | CVE-2014-3566 | S side | A (commit) | master handshake.c L712 precondition check (Category III) |
| 21 | 202392/333503 | php-src | CVE-2016-6207 | S side | A (commit) | master gd_interpolation.c rewrite; zero u-- in the whole file (Category III) |
| 22 | 195328/224472 | gpac | CVE-2021-40574 | S side | A (commit) | a5efec8187de+d0ced41651b2 two rounds of fixing; the commit title is the function name |
| 23 | 196801/245434 | gpac | CVE-2021-40567 | S side | A (commit) | 1b501e228490 rewrite removing gf_malloc+strcpy + b7b169d0cf83 fix null esd |
| 24 | 198161/269941 | ImageMagick | CVE-2016-10070 | S side | A (commit) | master coders/mat.c DestroyQuantumInfo x4 vs snapshot x1 (Category III) |
| 25 | 195274/223728 | tensorflow | CVE-2022-23589 | S side | B (runtime) | grappler conv child-node GetNode without a null check (mul side already fixed; asymmetric) (native SIGSEGV(139) + differential controls)|
| 26 | 195691/231012 | mruby | CVE-2022-1427 | S side | B (runtime) | OP_ARGARY lv==0 branch: stack[m1+r+m2] without an nregs bound (ASAN heap-buffer-overflow)|
| 27 | 197305/256441 | pjproject | CVE-2022-24786 | S side | B (runtime) | RTCP RPSI padlen over-read (guard short by 2 bytes; the sister bug in the same function is already fixed) (ASAN heap-buffer-overflow)|
| 28 | 198695/281247 | MilkyTracker | CVE-2019-14464 | S side | B (runtime) | S3M ordnum word read without clamping; the 255 marker is the only brake (ASAN stack-buffer-overflow WRITE)|
| 29 | 199952/295887 | MilkyTracker | CVE-2022-34927 | S side | B (runtime) | XM decode-loop over-read (ASAN heap-buffer-overflow READ)|
| 30 | 204115/353015 | openldap | CVE-2021-27212 | S side | B (runtime) | issuer-segment cursor wrap-around over-read (the CVE fixed only the thisUpdate half) (ASAN heap-buffer-overflow, extraction-level)|
| 31 | 198449/274814 | pjproject | CVE-2022-31031 | S side | B (runtime) | STUN header reads 2 bytes before validating them (ASAN heap-buffer-overflow)|
| 32 | 217551/522438 | elfspirit | CVE-2022-21711 | S side | B (runtime) | ELF e_shoff wild pointer (ASAN SEGV)|
| 33 | 195391/225125 | tensorflow | CVE-2022-21733 | S side | B (runtime) | ngrams fallback path lacks a sum upper bound (the fix checks only the pad_width>=0 half) (native SIGSEGV(139) + differential controls)|
| 34 | 195309/224281 | squid | CVE-2021-46784 | S side | B (runtime) | gopherToHTML 4096 line buffer 1B over-write (v5 carries the bug / v6 removed the module) - ASAN global-buffer-overflow WRITE |
| 35 | 210206/430470 | squid | CVE-2021-46784 | S side | B (runtime) | gopherToHTML 4096 line buffer 1B over-write (v5 carries the bug / v6 removed the module) - ASAN global-buffer-overflow WRITE |
| 36 | 210420/434902 | ghostpdl | CVE-2016-10317 | S side | C (source diff) | V/S function bodies verbatim identical; sole difference = function-name spelling fill_threshhold -> fill_threshold |
| 37 | 210834/440872 | xserver | CVE-2018-14665 | S side | C (source diff) | V/S code has zero differences; sole difference = S has 2 extra comment lines |
| 38 | 216812/506696 | openssl | CVE-2020-1971 | V side | C (source diff) | V/S are both the test-registration function setup_tests; the diff is only the single +ADD_TEST line; the real vulnerability is in library code, not in the samples |
| 39 | 215142/484063 | open62541 | CVE-2022-25761 | V side | C (source diff) | the filename is itself the test plugin check_securechannel.c; the V-side 65535 hardcode is inconsistent with the default sendBufferSize |

## 2. Evidence Classification (Three Methods)

- **Class A, upstream commit forensics (24 pairs, all on the S side)**: the S row is labeled "fixed version" (target=0), but its snapshot **predates the real fix commit** -- the upstream repository later contains the genuine fix (whose commit message self-admits the vulnerability or carries a CVE number); that commit's pre-version matches the S sample, and the guard introduced by the fix is absent from S. Forensic method: actually pull the fix commit's patch from GitHub/GitLab and compare it line by line against the S sample (Category I); or actually pull the current master file and compare at line level (Category III). All 24 pairs were re-verified online.
- **Class B, runtime crash empirical evidence (11 pairs, all on the S side)**: after compiling the S sample's code in its upstream true form (master / the S-version commit / the v5 branch), we **reproduced the crash by hand** with crafted malicious input (ASAN report or native SIGSEGV). Of these, 9 pairs are active-unfixed and 2 are removal-type (squid v5 carries the bug; v6 deleted the gopher module entirely). The reproduction scripts for each pair are in Section 4.
- **Class C, source-code comparison self-evidence (4 pairs)**: placing the paired V/S source rows from the dataset side by side is self-evidencing -- 2 of them (S side): the V/S function bodies are identical, so S cannot be the fixed version; the other 2 (V side): the samples are actually unit-test code, not vulnerability code.

---

## 3. Class A, 24 Pairs: Upstream Commit Forensics (S-side Label Errors)

Decision logic: the S row's snapshot predates the real fix commit => S still carries the vulnerability => target=0 is mislabeled. Re-verification per pair: pull the upstream fix commit's patch online and verify (a) the guard/changes introduced by the fix are absent from the S sample; (b) the patch's pre-image (deleted lines) matches S.

### A-1. 195752/232405 (tensorflow, CVE-2021-37647)

- **CWE**: CWE-476
- **Upstream evidence**: 965b97e4a + 000e37b4b (SparseTensorSliceDataset validation completed)
- **Online re-check**: pre 17/17 lines land in S

### A-2. 198116/269323 (tensorflow, CVE-2021-37635)

- **CWE**: CWE-125
- **Upstream evidence**: 6d3238fc9 (integer overflow and negative value check, including sparse_reduce_op.cc)
- **Online re-check**: file-level hunk pre-image hits S

### A-3. 195073/221123 (tensorflow, CVE-2022-23584)

- **CWE**: CWE-416
- **Upstream evidence**: ab51e5b (Prevent memory leak in decoding PNG images; decode_image_op.cc purely additive)
- **Online re-check**: the newly added guard is absent from S

### A-4. 195404/225563 (tensorflow, CVE-2022-21735)

- **CWE**: CWE-369
- **Upstream evidence**: 216525144ee7 + ee50d1e00f81 (FractionalMax/AVGPool pooling_ratio lower-bound guard)
- **Online re-check**: pooling_ratio_[i] >= 1 absent from S (regex-verified)

### A-5. 210904/442815 (curl, CVE-2018-16842)

- **CWE**: CWE-125
- **Upstream evidence**: d530e92f59ae (the CVE's own fix; diff verbatim len -= cut -> len -= cut + 1)
- **Online re-check**: online re-check passed

### A-6. 212834/462409 (rsyslog, CVE-2018-16881)

- **CWE**: CWE-190
- **Upstream evidence**: 89955b0bc (CVE-2022-24903; one commit sweeping the three modules tcps_sess/imptcp/imhttp)
- **Online re-check**: online re-check passed

### A-7. 210271/432093 (vim, CVE-2022-2923)

- **CWE**: CWE-787
- **Upstream evidence**: a80874d9b84a (spellfile.c OOB write; two else -> else if (depth < MAXWLEN - 1) guards)
- **Online re-check**: guard count 0 in S (S contains the unbounded depth++ loop)

### A-8. 195909/234875 (ImageMagick, CVE-2017-13139)

- **CWE**: CWE-125
- **Upstream evidence**: master png.c (ReadOneMNGImage) -- off-by-one clamping fix: the S snapshot clamps an over-large object_id to `object_id=MNG_MAX_OBJECTS;` (still 1 past the array bound), while master changed it to `object_id=MNG_MAX_OBJECTS-1;` (legal)
- **Online re-check**: the L5357 line-level hit falls inside the function body (an actual pull of master); a later re-check of the IM7 main branch found that fix line and the "object id too large" error present, while the S snapshot's clamping line lacks the `-1` -- the off-by-one verdict stands

### A-9. 215038/482692 (gst-plugins-good, CVE-2016-9810)

- **CWE**: CWE-125
- **Upstream evidence**: 153a8ae (flxdec rewrite)
- **Online re-check**: pre 65/227 lines land in S

### A-10. 210702/439500 (squashfs-tools, CVE-2021-40153)

- **CWE**: CWE-22
- **Upstream evidence**: 2bf96e1ec (unsquash-4.c; official mate re-confirmed)
- **Online re-check**: pre 12/18 lines land in both V/S (verified against the true mate)

### A-11. 210700/439495 (squashfs-tools, CVE-2021-40153)

- **CWE**: CWE-22
- **Upstream evidence**: 2bf96e1ec
- **Online re-check**: same commit as 210702, already verified

### A-12. 210701/439495 (squashfs-tools, CVE-2021-40153)

- **CWE**: CWE-22
- **Upstream evidence**: 2bf96e1ec (also a pairing failure; see the separate archive)
- **Online re-check**: same commit

### A-13. 211700/450830 (linux, CVE-2022-26490)

- **CWE**: CWE-120
- **Upstream evidence**: 77e5fe8f17 + f2e19b3659 + 996419e059 (nfc st21nfca se.c validation logic)
- **Online re-check**: pre 1/1 line lands in S

### A-14. 212083/454759 (linux, CVE-2022-3077)

- **CWE**: CWE-703
- **Upstream evidence**: 39244cc75482 (i2c-ismt out-of-bounds; the commit embeds a KASAN log)
- **Online re-check**: guard absent from S

### A-15. 202719/337848 (linux, CVE-2022-0322)

- **CWE**: CWE-704
- **Upstream evidence**: 18ae07691d43 (sctp; the commit message explicitly names the sctp_make_strreset_req __u16 overflow, guard added on the caller side)
- **Online re-check**: online re-check passed

### A-16. 197824/264657 (gpac, CVE-2022-1795)

- **CWE**: CWE-416
- **Upstream evidence**: bf35245e (same-day c535bad5 reverted a typo; memory_decoder.c)
- **Online re-check**: pre 2/2 lines land in S

### A-17. 202688/336807 (ghostpdl, CVE-2020-16287)

- **CWE**: CWE-787
- **Upstream evidence**: 234110d58955 + 4763e7f89953 (gdevlprn.g: <0 changed to <=0 closing the BlockWidth==0 precondition + overflow guard)
- **Online re-check**: both patches obtained

### A-18. 198927/285157 (radare2, CVE-2022-1297)

- **CWE**: CWE-125
- **Upstream evidence**: 48f0ea79f (ne.c; guard added in r_bin_ne_get_segments -- the V function calls it at line 8)
- **Online re-check**: online re-check passed

### A-19. 207780/401034 (radare2, CVE-2022-1244)

- **CWE**: CWE-703
- **Upstream evidence**: master bin_dyldcache.c guard (Category III)
- **Online re-check**: the L479 dep_index >= imagesCount and L610-611 depListCount guards are verbatim present

### A-20. 201872/325821 (gnutls, CVE-2014-3566)

- **CWE**: CWE-310
- **Upstream evidence**: master handshake.c precondition check (Category III, official gitlab repository)
- **Online re-check**: L712 `suite_size == 0 || (suite_size % 2) != 0` verbatim present; a later re-check found the same check present at L694 (the line number drifted as the file evolved, the content is verbatim unchanged); the S sample's function is `_gnutls_server_select_suite` and lacks this check

### A-21. 202392/333503 (php-src, CVE-2016-6207)

- **CWE**: CWE-119
- **Upstream evidence**: master gd_interpolation.c rewrite (Category III)
- **Online re-check**: _gdContributionsFree rewritten with an independent cursor; zero u-- in the whole file

### A-22. 195328/224472 (gpac, CVE-2021-40574)

- **CWE**: CWE-415
- **Upstream evidence**: a5efec8187de + d0ced41651b2 (gftext_get_utf8_line fixed twice; the commit title is the function name)
- **Online re-check**: patch obtained; guard absent from S

### A-23. 196801/245434 (gpac, CVE-2021-40567)

- **CWE**: CWE-703
- **Upstream evidence**: 1b501e228490 (isom_hinter.c rewrite removing two gf_malloc+strcpy sites) + b7b169d0cf83 (fix null esd, fixes #3049)
- **Online re-check**: patch hunk original text seen firsthand

### A-24. 198161/269941 (ImageMagick, CVE-2016-10070)

- **CWE**: CWE-125
- **Upstream evidence**: master coders/mat.c (Category III)
- **Online re-check**: DestroyQuantumInfo x4 inside ReadMATImage vs x1 in the snapshot; the actual pull of master matched the count

---

## 4. Class B, 11 Pairs: Runtime Crash Empirical Evidence (S-side Label Errors)

Overall method: compile the upstream source with **zero modifications** (ASAN or native), craft malicious input, and run the real loading path.
All 11 pairs had their crashes reproduced by hand (9 ASAN/SEGV + the two TensorFlow pairs with native SIGSEGV).

**Reproduction scripts are archived separately under the `runtime_repro/` directory** (one subdirectory per pair, containing the PoC, harness, control scripts, and input-construction scripts).

| # | Pair (V/S) | Mechanism | Reproduction script directory | Crash (log) |
|---|---|---|---|---|
| B-1 | 195274/223728 | in grappler MulConvPushDown, taking the conv child node of mul(const_w, conv) via GetNode has no null check (master L3573-3576 asymmetric with the mul side -- the mul side is the already-fixed CVE-2022-23589); differential controls: dangling conv child attached -> crash(139), mul child attached (fixed side) -> clean error, plain Add attached -> clean error | `runtime_repro/B1_tensorflow_223728/` (poc + two controls) | native SIGSEGV 139 (including evidence of the "error is tolerated" path) |
| B-2 | 195391/225125 | the CVE-2022-21733 fix in StringNGrams added only the pad_width>=0 half; the preserve_short fallback path has no sum upper bound on data_length+2*pad_width -> overflows int32 at 2^30 -> wild access with negative width; differential controls: pad_width=2 normal, -5 cleanly intercepted by the fixed half, 2^30 crashes | `runtime_repro/B2_tensorflow_225125/` (poc + parameterized control) | native SIGSEGV 139 |
| B-3 | 195691/231012 | crafted bytecode makes the OP_ARGARY operands lv=0 and m1/m2=31, with stack[m1+r+m2] lacking an nregs bound; at recursion depth 14 the block frames are pushed into a stack-slack window < 62 and it crashes (threat model = the CVE-2022-1208 family) | `runtime_repro/B3_mruby_231012/` (source program + operand-patching script + ready-made PoC) | ASAN heap-buffer-overflow; the crash stack passes through the vm.c:2033 core line |
| B-4 | 197305/256441 | RTCP RPSI: a packet allocated at exactly 12 bytes; the guard length < rpsi_len+12 (12<12, false) lets it through and then reads buf[12] -- the guard is short by the two padlen/pt bytes (+2); the sister bug in the same function was already fixed by f67e3ed240fc (ironclad asymmetry-in-place evidence) | `runtime_repro/B4_B5_pjproject/` (one-binary three-mode harness) | ASAN heap-buffer-overflow READ 1B, rtcp_fb.c:783 |
| B-5 | 198449/274814 | STUN: the entry assertion only guarantees pdu_len>=1; the length field is read before the length check, reading pdu[2..3] out of bounds by 2B | same as above (harness mode 3) | ASAN heap-buffer-overflow READ 2B, stun_msg.c:2380 (stun_full.log) |
| B-6 | 198695/281247 | S3M ordnum=0xFFFF with no 255 brake marker in the order table; LoaderS3M.cpp:399 writes through the ord[MP_MAXORDERS=256] stack object | `runtime_repro/B6_B7_milkytracker/` (loading harness + two PoC input files) | ASAN stack-buffer-overflow WRITE |
| B-7 | 199952/295887 | XM rows=100 with patdata exactly 100 bytes; the decode loop consumes 100 slots x 5B = 500 bytes and over-reads the heap buffer | same as above (harness with poc2.xm) | ASAN heap-buffer-overflow READ, LoaderXM.cpp:370 |
| B-8 | 204115/353015 | an issuer quoted-string double-quote escape makes is->bv_len += 2 go past the window -> x.bv_len -= is->bv_len+1 wraps around to -1 -> eat-spaces over-reads 1B; CVE-2021-27212 fixed only the thisUpdate half (2.6.15/2.7.1 dual-version direct evidence) | `runtime_repro/B8_openldap_353015/` (harness + verbatim-extracted function body) | ASAN heap-buffer-overflow READ (forensics level = function-level extraction, one tier weaker than the full binary) |
| B-9 | 217551/522438 | a 64-byte minimal ELF64 with e_shoff=0xFFFFFF00 wild section-table offset -> dereferenced in init | `runtime_repro/B9_elfspirit_522438/` (tiny_elf + rebuild script; output byte-for-byte identical) | ASAN SEGV, elfutil.c:174 |
| B-10/11 | 195309/224281, 210206/430470 | inside gopherToHTML, LOCAL_ARRAY(char,line,4096): 4094B+\n makes llen=4095, the guard 4095>=4096 is false and does not trigger, and line[4096] is over-written by 1B; v5 carries the bug to this day and v6 deleted the gopher module (removal-type dual characterization) | `runtime_repro/B10_B11_squid_gopher/` (fake server + proxy request + squid.conf trio) | ASAN global-buffer-overflow WRITE 1B landing exactly on line[4096], with the variable's content being 4094 A's; toolchain pitfall: GCC ASAN does not instrument function-local static arrays, clang O1 is required; the URL type must be 1 = directory |

## 5. Class C, 4 Pairs: Source-Code Comparison Self-Evidence

### C-1. 210420 / 434902 (ghostpdl, CVE-2016-10317)

The function bodies of the V and S rows are **verbatim identical** (24 lines); the sole difference is one line of function-name spelling: the V side is `fill_threshhold_buffer` (old spelling, one extra h) and the S side is `fill_threshold_buffer` (a later upstream rename to unify the spelling). A rename is not a vulnerability fix -- the two rows of code behave identically; if one row is the vulnerability (target=1) and the other the fix (target=0), then the same code is simultaneously the vulnerability and the fix, so one of the two labels must be wrong. The real CVE-2016-10317 fix happened in a different commit, not in this pair's diff.

**V-side original text (dataset idx=210420, target=1), 24 lines:**

```c
fill_threshhold_buffer(byte *dest_strip, byte *src_strip, int src_width,
                       int left_offset, int left_width, int num_tiles,
                       int right_width)
{
    byte *ptr_out_temp = dest_strip;
    int ii;

    /* Left part */
    memcpy(dest_strip, src_strip + left_offset, left_width);
    ptr_out_temp += left_width;
    /* Now the full parts */
    for (ii = 0; ii < num_tiles; ii++){
        memcpy(ptr_out_temp, src_strip, src_width);
        ptr_out_temp += src_width;
    }
    /* Now the remainder */
    memcpy(ptr_out_temp, src_strip, right_width);
#ifdef PACIFY_VALGRIND
    ptr_out_temp += right_width;
    ii = (dest_strip-ptr_out_temp) % (LAND_BITS-1);
    if (ii > 0)
        memset(ptr_out_temp, 0, ii);
#endif
}
```

**S-side original text (dataset idx=434902, target=0), 24 lines:**

```c
fill_threshold_buffer(byte *dest_strip, byte *src_strip, int src_width,
                       int left_offset, int left_width, int num_tiles,
                       int right_width)
{
    byte *ptr_out_temp = dest_strip;
    int ii;

    /* Left part */
    memcpy(dest_strip, src_strip + left_offset, left_width);
    ptr_out_temp += left_width;
    /* Now the full parts */
    for (ii = 0; ii < num_tiles; ii++){
        memcpy(ptr_out_temp, src_strip, src_width);
        ptr_out_temp += src_width;
    }
    /* Now the remainder */
    memcpy(ptr_out_temp, src_strip, right_width);
#ifdef PACIFY_VALGRIND
    ptr_out_temp += right_width;
    ii = (dest_strip-ptr_out_temp) % (LAND_BITS-1);
    if (ii > 0)
        memset(ptr_out_temp, 0, ii);
#endif
}
```

### C-2. 210834 / 440872 (xserver, CVE-2018-14665)

The V and S rows of code have **zero differences**; the only difference is 2 extra comment lines on the S side (/* the format string below is controlled by the user, this code should never be called with elevated privileges */) -- zero behavioral change. A comment does not constitute a fix, so one of the two labels must be wrong. The real CVE-2018-14665 fix is not in this pair's diff.

**V-side original text (dataset idx=210834, target=1), 36 lines:**

```c
LogFilePrep(const char *fname, const char *backup, const char *idstring)
{
    char *logFileName = NULL;

    if (asprintf(&logFileName, fname, idstring) == -1)
        FatalError("Cannot allocate space for the log file name\n");

    if (backup && *backup) {
        struct stat buf;

        if (!stat(logFileName, &buf) && S_ISREG(buf.st_mode)) {
            char *suffix;
            char *oldLog;

            if ((asprintf(&suffix, backup, idstring) == -1) ||
                (asprintf(&oldLog, "%s%s", logFileName, suffix) == -1)) {
                FatalError("Cannot allocate space for the log file name\n");
            }
            free(suffix);

            if (rename(logFileName, oldLog) == -1) {
                FatalError("Cannot move old log file \"%s\" to \"%s\"\n",
                           logFileName, oldLog);
            }
            free(oldLog);
        }
    }
    else {
        if (remove(logFileName) != 0 && errno != ENOENT) {
            FatalError("Cannot remove old log file \"%s\": %s\n",
                       logFileName, strerror(errno));
        }
    }

    return logFileName;
}
```

**S-side original text (dataset idx=440872, target=0), 38 lines:**

```c
LogFilePrep(const char *fname, const char *backup, const char *idstring)
{
    char *logFileName = NULL;

    /* the format string below is controlled by the user,
       this code should never be called with elevated privileges */
    if (asprintf(&logFileName, fname, idstring) == -1)
        FatalError("Cannot allocate space for the log file name\n");

    if (backup && *backup) {
        struct stat buf;

        if (!stat(logFileName, &buf) && S_ISREG(buf.st_mode)) {
            char *suffix;
            char *oldLog;

            if ((asprintf(&suffix, backup, idstring) == -1) ||
                (asprintf(&oldLog, "%s%s", logFileName, suffix) == -1)) {
                FatalError("Cannot allocate space for the log file name\n");
            }
            free(suffix);

            if (rename(logFileName, oldLog) == -1) {
                FatalError("Cannot move old log file \"%s\" to \"%s\"\n",
                           logFileName, oldLog);
            }
            free(oldLog);
        }
    }
    else {
        if (remove(logFileName) != 0 && errno != ENOENT) {
            FatalError("Cannot remove old log file \"%s\": %s\n",
                       logFileName, strerror(errno));
        }
    }

    return logFileName;
}
```

### C-3. 216812 / 506696 (openssl, CVE-2020-1971)

The V and S rows are **both the test-registration function setup_tests**, not vulnerability code: the diff is only the single line `+ADD_TEST(test_GENERAL_NAME_cmp);` -- a ripple hunk in which the fix commit **newly registers a test case** for the double-free regression test, not the vulnerability fix itself. The real CVE-2020-1971 vulnerability (GENERAL_NAME_cmp double-free) is in the library code crypto/x509v3/v3_genn.c, not inside the samples' function bodies.

**V-side original text (dataset idx=216812, target=1), 5 lines:**

```c
int setup_tests(void)
{
    ADD_ALL_TESTS(call_run_cert, OSSL_NELEM(name_fns));
    return 1;
}
```

**S-side original text (dataset idx=506696, target=0), 6 lines:**

```c
int setup_tests(void)
{
    ADD_ALL_TESTS(call_run_cert, OSSL_NELEM(name_fns));
    ADD_TEST(test_GENERAL_NAME_cmp);
    return 1;
}
```

### C-4. 215142 / 484063 (open62541, CVE-2022-25761)

The filename is itself the test plugin `check_securechannel.c` (unit-test code, not product code). The diff changes the V side's `createDummyConnection(65535, ...)` hardcoded size to the S side's reference to `UA_ConnectionConfig_default.sendBufferSize` -- what was fixed is **consistency between the test stub and the default configuration** (test-infrastructure cleanup), not a vulnerability fix. The real CVE-2022-25761 vulnerability is in the product code, not inside the test samples.

**V-side original text (dataset idx=215142, target=1), 11 lines:**

```c
setup_secureChannel(void) {
    TestingPolicy(&dummyPolicy, dummyCertificate, &fCalled, &keySizes);
    UA_SecureChannel_init(&testChannel, &UA_ConnectionConfig_default);
    UA_SecureChannel_setSecurityPolicy(&testChannel, &dummyPolicy, &dummyCertificate);

    testingConnection = createDummyConnection(65535, &sentData);
    UA_Connection_attachSecureChannel(&testingConnection, &testChannel);
    testChannel.connection = &testingConnection;

    testChannel.state = UA_SECURECHANNELSTATE_OPEN;
}
```

**S-side original text (dataset idx=484063, target=0), 12 lines:**

```c
setup_secureChannel(void) {
    TestingPolicy(&dummyPolicy, dummyCertificate, &fCalled, &keySizes);
    UA_SecureChannel_init(&testChannel, &UA_ConnectionConfig_default);
    UA_SecureChannel_setSecurityPolicy(&testChannel, &dummyPolicy, &dummyCertificate);

    testingConnection =
        createDummyConnection(UA_ConnectionConfig_default.sendBufferSize, &sentData);
    UA_Connection_attachSecureChannel(&testingConnection, &testChannel);
    testChannel.connection = &testingConnection;

    testChannel.state = UA_SECURECHANNELSTATE_OPEN;
}
```

