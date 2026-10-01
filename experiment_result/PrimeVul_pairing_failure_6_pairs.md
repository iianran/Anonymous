# PrimeVul Test Set Pairing Failures: Details of the Six Pairs 

## I. Master List

| # | Pair ID (V-row idx) | S-row idx | Project | CVE | Files Involved | Failure Type |
|---|---|---|---|---|---|---|
| 1 | 207755 | 400779 | php-src | CVE-2012-6113 | ext/openssl/openssl.c | Different-function mismatch (adjacent function) |
| 2 | 197511 | 259619 | libjpeg | CVE-2022-31796 | control/hierarchicalbitmaprequester.cpp | Different-function mismatch (sister function) |
| 3 | 208535 | 412332 | rizin | CVE-2022-36043 | librz/bin/p/bin_qnx.c | Different-function mismatch (next-door function) |
| 4 | 215391 | 489124 | linux-2.6 | CVE-2008-4618 | net/sctp/sm_statefuns.c | Different-function mismatch (sister function) |
| 5 | 204016 | 349259 | squashfs-tools | CVE-2021-41072 | unsquash-1/2.c (V) / unsquash-3.c (S) | Cross-file twin duplicate row |
| 6 | 210701 | 439495 | squashfs-tools | CVE-2021-40153 | unsquash-3.c (V) / unsquash-1/2.c (S) | Cross-file twin duplicate row |


---

## Pair 1: 207755 / 400779 (php-src, CVE-2012-6113)

- **Project**: php-src (https://github.com/php/php-src)
- **CVE / CWE**:CVE-2012-6113 / CWE-200
- **Fix commit**:095cbc48a8f0090f3b0abc6155f2b61943c9eafb(identical in both V/S rows)

**Pairing failure cause**: The V side (207755) and the S side (400779) are not the same function at all -- the first line of each code snippet is enough to tell them apart: V is `PHP_FUNCTION(openssl_encrypt)` (the encryption entry point) and S is `PHP_FUNCTION(openssl_decrypt)` (the decryption entry point), two PHP built-in functions sitting immediately one after the other in ext/openssl/openssl.c. The vulnerability is on the encrypt side: old OpenSSL (before 0.9.8i) crashes with a null-pointer dereference inside `EVP_EncryptUpdate` when handed empty plaintext with `data_len == 0` (the commit message is precisely "Fix segfault in older versions of OpenSSL"). Fix commit 095cbc48a8f0 has only one small change in all of openssl.c: adding an `if (data_len > 0)` guard inside the encrypt function (+3/-1, a single hunk); decrypt was not touched by a single line. When extracting the pair, the dataset mistook the decrypt function, adjacent within the same commit and the same file, for the "post-fix version" -- but that guard is nowhere to be found in the S-side code, because the fix simply is not in that code. Forensic method: the commit's patch has only 1 hunk, and the 1 deleted source line matches V 1/1 and S 0 times, which establishes that S has nothing to do with the fix.

- **Correct partner should be**: the post-fix version of `openssl_encrypt` with the `if (data_len > 0)` guard added.
- **Upstream forensics**: original patch file of commit 095cbc48a8f0, retrieved from the upstream repository.

### V-side original text (idx=207755 in the dataset, target=1, vulnerable version, 70 lines)

```c
PHP_FUNCTION(openssl_encrypt)
{
	zend_bool raw_output = 0;
	char *data, *method, *password, *iv = "";
	int data_len, method_len, password_len, iv_len = 0, max_iv_len;
	const EVP_CIPHER *cipher_type;
	EVP_CIPHER_CTX cipher_ctx;
	int i, outlen, keylen;
	unsigned char *outbuf, *key;
	zend_bool free_iv;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|bs", &data, &data_len, &method, &method_len, &password, &password_len, &raw_output, &iv, &iv_len) == FAILURE) {
		return;
	}
	cipher_type = EVP_get_cipherbyname(method);
	if (!cipher_type) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher algorithm");
		RETURN_FALSE;
	}

	keylen = EVP_CIPHER_key_length(cipher_type);
	if (keylen > password_len) {
		key = emalloc(keylen);
		memset(key, 0, keylen);
		memcpy(key, password, password_len);
	} else {
		key = (unsigned char*)password;
	}

	max_iv_len = EVP_CIPHER_iv_length(cipher_type);
	if (iv_len <= 0 && max_iv_len > 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Using an empty Initialization Vector (iv) is potentially insecure and not recommended");
	}
	free_iv = php_openssl_validate_iv(&iv, &iv_len, max_iv_len TSRMLS_CC);

	outlen = data_len + EVP_CIPHER_block_size(cipher_type);
	outbuf = emalloc(outlen + 1);

	EVP_EncryptInit(&cipher_ctx, cipher_type, NULL, NULL);
	if (password_len > keylen) {
		EVP_CIPHER_CTX_set_key_length(&cipher_ctx, password_len);
	}
	EVP_EncryptInit_ex(&cipher_ctx, NULL, NULL, key, (unsigned char *)iv);
	EVP_EncryptUpdate(&cipher_ctx, outbuf, &i, (unsigned char *)data, data_len);
	outlen = i;
	if (EVP_EncryptFinal(&cipher_ctx, (unsigned char *)outbuf + i, &i)) {
		outlen += i;
		if (raw_output) {
			outbuf[outlen] = '\0';
			RETVAL_STRINGL((char *)outbuf, outlen, 0);
		} else {
			int base64_str_len;
			char *base64_str;

			base64_str = (char*)php_base64_encode(outbuf, outlen, &base64_str_len);
			efree(outbuf);
			RETVAL_STRINGL(base64_str, base64_str_len, 0);
		}
	} else {
		efree(outbuf);
		RETVAL_FALSE;
	}
	if (key != (unsigned char*)password) {
		efree(key);
	}
	if (free_iv) {
		efree(iv);
	}
	EVP_CIPHER_CTX_cleanup(&cipher_ctx);
}
```

### S-side original text (idx=400779 in the dataset, target=0, mispaired "fixed version", 74 lines)

```c
PHP_FUNCTION(openssl_decrypt)
{
	zend_bool raw_input = 0;
	char *data, *method, *password, *iv = "";
	int data_len, method_len, password_len, iv_len = 0;
	const EVP_CIPHER *cipher_type;
	EVP_CIPHER_CTX cipher_ctx;
	int i, outlen, keylen;
	unsigned char *outbuf, *key;
	int base64_str_len;
	char *base64_str = NULL;
	zend_bool free_iv;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|bs", &data, &data_len, &method, &method_len, &password, &password_len, &raw_input, &iv, &iv_len) == FAILURE) {
		return;
	}

	if (!method_len) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher algorithm");
		RETURN_FALSE;
	}

	cipher_type = EVP_get_cipherbyname(method);
	if (!cipher_type) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher algorithm");
		RETURN_FALSE;
	}

	if (!raw_input) {
		base64_str = (char*)php_base64_decode((unsigned char*)data, data_len, &base64_str_len);
		data_len = base64_str_len;
		data = base64_str;
	}

	keylen = EVP_CIPHER_key_length(cipher_type);
	if (keylen > password_len) {
		key = emalloc(keylen);
		memset(key, 0, keylen);
		memcpy(key, password, password_len);
	} else {
		key = (unsigned char*)password;
	}

	free_iv = php_openssl_validate_iv(&iv, &iv_len, EVP_CIPHER_iv_length(cipher_type) TSRMLS_CC);

	outlen = data_len + EVP_CIPHER_block_size(cipher_type);
	outbuf = emalloc(outlen + 1);

	EVP_DecryptInit(&cipher_ctx, cipher_type, NULL, NULL);
	if (password_len > keylen) {
		EVP_CIPHER_CTX_set_key_length(&cipher_ctx, password_len);
	}
	EVP_DecryptInit_ex(&cipher_ctx, NULL, NULL, key, (unsigned char *)iv);
	EVP_DecryptUpdate(&cipher_ctx, outbuf, &i, (unsigned char *)data, data_len);
	outlen = i;
	if (EVP_DecryptFinal(&cipher_ctx, (unsigned char *)outbuf + i, &i)) {
		outlen += i;
		outbuf[outlen] = '\0';
		RETVAL_STRINGL((char *)outbuf, outlen, 0);
	} else {
		efree(outbuf);
		RETVAL_FALSE;
	}
	if (key != (unsigned char*)password) {
		efree(key);
	}
	if (free_iv) {
		efree(iv);
	}
	if (base64_str) {
		efree(base64_str);
	}
 	EVP_CIPHER_CTX_cleanup(&cipher_ctx);
}
```

---

## Pair 2: 197511 / 259619 (libjpeg, CVE-2022-31796)

- **Project**: libjpeg (https://github.com/thorfdbg/libjpeg)
- **CVE / CWE**:CVE-2022-31796 / CWE-787
- **Fix commit**:187035b9726710b4fe11d565c7808975c930895d(identical in both V/S rows)

**Pairing failure cause**: The V side (197511) is `HierarchicalBitmapRequester::PrepareForDecoding` (a decoding-preparation function), while the S side (259619) is the analogous `PrepareForEncoding` (an encoding-preparation function) -- the two function names differ only by the single word Dec/Enc, they sit right next to each other in control/hierarchicalbitmaprequester.cpp, and their code structure is nearly a mirror image (V operates on `m_ppDecodingMCU`/`m_ppUpsampler`, S on `m_ppEncodingMCU`/`m_ppDownsampler`); the textual similarity is extremely high, and this is exactly the kind of case automatic extraction gets wrong most easily. The vulnerability is an out-of-bounds write caused by inconsistent MCU sizes across the levels of a hierarchical JPEG; fix commit 187035b97267 only added 11 lines of cross-level subsampling consistency checks inside the body of `PrepareForDecoding` (`JPG_THROW(MALFORMED_STREAM)`, hunk @@ -245) and never touched Encoding. That is why no trace of those checks can be found in the S-side code -- it is not the fixed version of V, just another function that resembles V in both name and shape. Forensic method: the +11/-1 of the upstream patch lands inside the body of the Decoding function, and S has zero intersection with the patch.

- **Correct partner should be**: the post-fix version of `PrepareForDecoding` (with the 11-line consistency check inside its body).
- **Upstream forensics**: commit 187035b97267 patch: control/hierarchicalbitmaprequester.cpp +11/-1.

### V-side original text (idx=197511 in the dataset, target=1, vulnerable version, 35 lines)

```cpp
void HierarchicalBitmapRequester::PrepareForDecoding(void)
{
#if ACCUSOFT_CODE

  UBYTE i;

  BuildCommon();

  if (m_ppDecodingMCU == NULL) {
    m_ppDecodingMCU = (struct Line **)m_pEnviron->AllocMem(sizeof(struct Line *) * m_ucCount*8);
    memset(m_ppDecodingMCU,0,sizeof(struct Line *) * m_ucCount * 8);
  }

  if (m_ppUpsampler == NULL) {
    m_ppUpsampler = (class UpsamplerBase **)m_pEnviron->AllocMem(sizeof(class UpsamplerBase *) * m_ucCount);
    memset(m_ppUpsampler,0,sizeof(class Upsampler *) * m_ucCount);

    for(i = 0;i < m_ucCount;i++) {
      class Component *comp = m_pFrame->ComponentOf(i);
      UBYTE sx = comp->SubXOf();
      UBYTE sy = comp->SubYOf();

      if (sx > 1 || sy > 1) {
        m_ppUpsampler[i] = UpsamplerBase::CreateUpsampler(m_pEnviron,sx,sy,
                                                          m_ulPixelWidth,m_ulPixelHeight,
                                                          m_pFrame->TablesOf()->isChromaCentered());
        m_bSubsampling   = true;
      }
    }
  }

  if (m_pLargestScale)
    m_pLargestScale->PrepareForDecoding();
#endif
}
```

### S-side original text (idx=259619 in the dataset, target=0, mispaired "fixed version", 34 lines)

```cpp
void HierarchicalBitmapRequester::PrepareForEncoding(void)
{
#if ACCUSOFT_CODE
  
  BuildCommon();

  if (m_ppEncodingMCU == NULL) {
    m_ppEncodingMCU = (struct Line **)m_pEnviron->AllocMem(sizeof(struct Line *) * m_ucCount *8);
    memset(m_ppEncodingMCU,0,sizeof(struct Line *) * m_ucCount * 8);
  }
  
  if (m_ppDownsampler == NULL) {
    m_ppDownsampler = (class DownsamplerBase **)m_pEnviron->AllocMem(sizeof(class DownsamplerBase *) * m_ucCount);
    memset(m_ppDownsampler,0,sizeof(class DownsamplerBase *) * m_ucCount);
    
    for(UBYTE i = 0;i < m_ucCount;i++) {
      class Component *comp = m_pFrame->ComponentOf(i);
      UBYTE sx = comp->SubXOf();
      UBYTE sy = comp->SubYOf();

      if (sx > 1 || sy > 1) {
        m_ppDownsampler[i] = DownsamplerBase::CreateDownsampler(m_pEnviron,sx,sy,
                                                                m_ulPixelWidth,m_ulPixelHeight,
                                                                m_pFrame->TablesOf()->
                                                                isDownsamplingInterpolated());
        m_bSubsampling     = true;
      }
    }
  }

  if (m_pLargestScale)
    m_pLargestScale->PrepareForEncoding();
#endif
}
```

---

## Pair 3: 208535 / 412332 (rizin, CVE-2022-36043)

- **Project**: rizin (https://github.com/rizinorg/rizin)
- **CVE / CWE**:CVE-2022-36043 / CWE-415
- **Fix commit**:58926dffbe819fe9ebf5062f7130e026351cae01(identical in both V/S rows)

**Pairing failure cause**: This is the most immediately legible of the six pairs -- the two code snippets have outright different function names: V is `static RzList *relocs(...)` and S is `static RzList *maps(...)`. The two functions sit next to each other in librz/bin/p/bin_qnx.c and are verbatim identical except for the function name and the field read by the final return statement (V reads `qo->fixups`, S reads `qo->maps`). The vulnerability is in relocs: `rz_list_clone(qo->fixups)` performs only a shallow clone, so the returned list shares one and the same batch of `RzBinReloc` pointers with the QNX plugin's internal list, and when each side frees its own list that same batch of pointers gets freed twice (a double-free; the commit message is precisely "fix #2964 - double-free in bin_qnx.c"). Fix commit 58926dffbe81 replaced the shallow clone with a per-item `RZ_NEW0` deep-copy loop (+18/-1) and changed only relocs. The S side (maps) was never touched by this commit; its code still carries the one-line shallow-clone idiom `rz_list_clone(qo->maps)` to this day -- if it really were the "fixed version", that would mean the fix accomplished nothing; in fact the fix simply was not aimed at it.

- **Correct partner should be**: the post-fix version of `relocs` (with the deep-copy loop in place).
- **Upstream forensics**: commit 58926dffbe81 patch: librz/bin/p/bin_qnx.c +18/-1, landing only in the relocs function.

### V-side original text (idx=208535 in the dataset, target=1, vulnerable version, 5 lines)

```c
static RzList *relocs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	QnxObj *qo = bf->o->bin_obj;
	return rz_list_clone(qo->fixups);
}
```

### S-side original text (idx=412332 in the dataset, target=0, mispaired "fixed version", 5 lines)

```c
static RzList *maps(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	QnxObj *qo = bf->o->bin_obj;
	return rz_list_clone(qo->maps);
}
```

---

## Pair 4: 215391 / 489124 (linux-2.6, CVE-2008-4618)

- **Project**: linux-2.6 (http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6)
- **CVE / CWE**:CVE-2008-4618 / CWE-20
- **Fix commit**:ba0166708ef4da7eeb61dd92bbba4d5a749d6561(identical in both V/S rows)

**Pairing failure cause**: The V side (215391) is `sctp_sf_violation_paramlen` (handling "parameter length violations"), while the S side (489124) is `sctp_sf_violation_chunklen` (handling "chunk length violations") -- sister functions 18 lines apart in net/sctp/sm_statefuns.c; even their error-message strings differ by just one word (V: "The following **parameter** had invalid length:", S: "The following **chunk** had invalid length:"). The vulnerability is a type confusion: paramlen forwards the `struct sctp_paramhdr *` argument pointer handed over by the caller straight to `sctp_sf_abort_violation` as if it were a `struct sctp_chunk *` (see the last two lines of the V code); the callee then reads the chunk_hdr member according to the chunk layout, causing a kernel panic -- the commit message lays out this call chain very clearly. Fix commit ba0166708ef4 rewrote paramlen (adding a `void *ext` formal parameter to the signature and switching to `sctp_make_violation_paramlen` to build the abort packet correctly); across the 5 hunks in sm_statefuns.c, chunklen appears 0 times (2 hunks fall on paramlen -- the forward-declaration signature update and the function-body rewrite; the other 3 are argument-passing corrections in the callers do_asconf/do_asconf_ack); in the post-fix file the two functions sit at L4221(chunklen)/L4239(paramlen). The S-side chunklen was left untouched by this commit, so it is naturally not the fixed version of V.

- **Correct partner should be**: the post-fix version of `sctp_sf_violation_paramlen` (rewritten to 26 lines, with `void *ext` in the signature).
- **Upstream forensics**: commit ba0166708ef4 patch (5 hunks in sm_statefuns.c, zero touches on chunklen) + line-number cross-check against the post-fix file.

### V-side original text (idx=215391 in the dataset, target=1, vulnerable version, 11 lines)

```c
static sctp_disposition_t sctp_sf_violation_paramlen(
				     const struct sctp_endpoint *ep,
				     const struct sctp_association *asoc,
				     const sctp_subtype_t type,
				     void *arg,
				     sctp_cmd_seq_t *commands) {
	static const char err_str[] = "The following parameter had invalid length:";

	return sctp_sf_abort_violation(ep, asoc, arg, commands, err_str,
					sizeof(err_str));
}
```

### S-side original text (idx=489124 in the dataset, target=0, mispaired "fixed version", 12 lines)

```c
static sctp_disposition_t sctp_sf_violation_chunklen(
				     const struct sctp_endpoint *ep,
				     const struct sctp_association *asoc,
				     const sctp_subtype_t type,
				     void *arg,
				     sctp_cmd_seq_t *commands)
{
	static const char err_str[]="The following chunk had invalid length:";

	return sctp_sf_abort_violation(ep, asoc, arg, commands, err_str,
					sizeof(err_str));
}
```

---

## Pair 5: 204016 / 349259 (squashfs-tools, CVE-2021-41072)

- **Project**: squashfs-tools (https://github.com/plougher/squashfs-tools)
- **CVE / CWE**:CVE-2021-41072 / CWE-200
- **Fix commit**:e0485802ec72996c20026da320650d8362f555bd(identical in both V/S rows)

**Pairing failure cause**: To support the four generations of Squashfs on-disk formats v1-v4, unsquashfs maintains one copy of the identically named `squashfs_opendir` in each of the four files unsquash-1.c / unsquash-2.c / unsquash-3.c / unsquash-4.c -- the four twin copies look almost alike, yet each handles the directory structure of a different version. The V side of this pair (204016) verbatim-matches **the pre-fix version in unsquash-1.c and unsquash-2.c** (the code uses the `squashfs_dir_header_2`/`squashfs_dir_entry_2` structures and the empty-directory test `(*i)->data == 0`; the v1.x and v2.x directory structures are isomorphic and the function is verbatim identical in those two files, so there is no way -- and no need -- to pin down which copy it is), while the S side (349259) verbatim-matches **the post-fix version in unsquash-3.c** (structures with the `_3` suffix, the test `(*i)->data == 3`, the size formula `size = (*i)->data + bytes - 3`, and the only match for that file in the dataset) -- V and S are one disk-format generation apart, so S is not the fixed version of V. Fix commit e0485802ec72 (the second round of hardening against "writes escaping outside the target directory") changed all four files at once, each getting a directory-sorting + duplicate-name check; the tail of the S-side code does carry the `check_directory` fix artifact, but that belongs to the fix of unsquash-3.c and is not kin to the V side, which comes from the v1/v2 side. In addition, the row idx=349259 appears twice in the dataset as a verbatim copy (same idx, byte-identical content): its "rightful owner" is the 204017 pair (its V verbatim-matches the pre-fix version of unsquash-3.c, exactly the pre- and post-fix counterpart of 349259 within the same file -- a true pair); in the present pair it is a duplicated copy serving as filler.

- **Correct partner should be**: the post-fix version of `squashfs_opendir` from unsquash-1.c/unsquash-2.c (the very copy V was born from) -- it exists upstream but was not extracted into the dataset.
- **Upstream forensics**: commit e0485802ec72 changed all four of unsquash-1/2/3/4.c; the full pre/post texts of the four files were verbatim-matched against the dataset rows to pin down the generation (the function is verbatim identical in unsquash-1.c and unsquash-2.c, and the two are not distinguished).

### V-side original text (idx=204016 in the dataset, target=1, vulnerable version, 132 lines)

```c
static struct dir *squashfs_opendir(unsigned int block_start, unsigned int offset,
	struct inode **i)
{
	squashfs_dir_header_2 dirh;
	char buffer[sizeof(squashfs_dir_entry_2) + SQUASHFS_NAME_LEN + 1]
		__attribute__((aligned));
	squashfs_dir_entry_2 *dire = (squashfs_dir_entry_2 *) buffer;
	long long start;
	int bytes = 0;
	int dir_count, size, res;
	struct dir_ent *ent, *cur_ent = NULL;
	struct dir *dir;

	TRACE("squashfs_opendir: inode start block %d, offset %d\n",
		block_start, offset);

	*i = read_inode(block_start, offset);

	dir = malloc(sizeof(struct dir));
	if(dir == NULL)
		MEM_ERROR();

	dir->dir_count = 0;
	dir->cur_entry = NULL;
	dir->mode = (*i)->mode;
	dir->uid = (*i)->uid;
	dir->guid = (*i)->gid;
	dir->mtime = (*i)->time;
	dir->xattr = (*i)->xattr;
	dir->dirs = NULL;

	if ((*i)->data == 0)
		/*
		 * if the directory is empty, skip the unnecessary
		 * lookup_entry, this fixes the corner case with
		 * completely empty filesystems where lookup_entry correctly
		 * returning -1 is incorrectly treated as an error
		 */
		return dir;

	start = sBlk.s.directory_table_start + (*i)->start;
	offset = (*i)->offset;
	size = (*i)->data + bytes;

	while(bytes < size) {
		if(swap) {
			squashfs_dir_header_2 sdirh;
			res = read_directory_data(&sdirh, &start, &offset, sizeof(sdirh));
			if(res)
				SQUASHFS_SWAP_DIR_HEADER_2(&dirh, &sdirh);
		} else
			res = read_directory_data(&dirh, &start, &offset, sizeof(dirh));

		if(res == FALSE)
			goto corrupted;

		dir_count = dirh.count + 1;
		TRACE("squashfs_opendir: Read directory header @ byte position "
			"%d, %d directory entries\n", bytes, dir_count);
		bytes += sizeof(dirh);

		/* dir_count should never be larger than SQUASHFS_DIR_COUNT */
		if(dir_count > SQUASHFS_DIR_COUNT) {
			ERROR("File system corrupted: too many entries in directory\n");
			goto corrupted;
		}

		while(dir_count--) {
			if(swap) {
				squashfs_dir_entry_2 sdire;
				res = read_directory_data(&sdire, &start,
					&offset, sizeof(sdire));
				if(res)
					SQUASHFS_SWAP_DIR_ENTRY_2(dire, &sdire);
			} else
				res = read_directory_data(dire, &start,
					&offset, sizeof(*dire));

			if(res == FALSE)
				goto corrupted;

			bytes += sizeof(*dire);

			/* size should never be SQUASHFS_NAME_LEN or larger */
			if(dire->size >= SQUASHFS_NAME_LEN) {
				ERROR("File system corrupted: filename too long\n");
				goto corrupted;
			}

			res = read_directory_data(dire->name, &start, &offset,
								dire->size + 1);

			if(res == FALSE)
				goto corrupted;

			dire->name[dire->size + 1] = '\0';

			/* check name for invalid characters (i.e /, ., ..) */
			if(check_name(dire->name, dire->size + 1) == FALSE) {
				ERROR("File system corrupted: invalid characters in name\n");
				goto corrupted;
			}

			TRACE("squashfs_opendir: directory entry %s, inode "
				"%d:%d, type %d\n", dire->name,
				dirh.start_block, dire->offset, dire->type);

			ent = malloc(sizeof(struct dir_ent));
			if(ent == NULL)
				MEM_ERROR();

			ent->name = strdup(dire->name);
			ent->start_block = dirh.start_block;
			ent->offset = dire->offset;
			ent->type = dire->type;
			ent->next = NULL;
			if(cur_ent == NULL)
				dir->dirs = ent;
			else
				cur_ent->next = ent;
			cur_ent = ent;
			dir->dir_count ++;
			bytes += dire->size + 1;
		}
	}

	return dir;

corrupted:
	squashfs_closedir(dir);
	return NULL;
}
```

### S-side original text (idx=349259 in the dataset, target=0, mispaired "fixed version", 138 lines)

```c
static struct dir *squashfs_opendir(unsigned int block_start, unsigned int offset,
	struct inode **i)
{
	squashfs_dir_header_3 dirh;
	char buffer[sizeof(squashfs_dir_entry_3) + SQUASHFS_NAME_LEN + 1]
		__attribute__((aligned));
	squashfs_dir_entry_3 *dire = (squashfs_dir_entry_3 *) buffer;
	long long start;
	int bytes = 0;
	int dir_count, size, res;
	struct dir_ent *ent, *cur_ent = NULL;
	struct dir *dir;

	TRACE("squashfs_opendir: inode start block %d, offset %d\n",
		block_start, offset);

	*i = read_inode(block_start, offset);

	dir = malloc(sizeof(struct dir));
	if(dir == NULL)
		MEM_ERROR();

	dir->dir_count = 0;
	dir->cur_entry = NULL;
	dir->mode = (*i)->mode;
	dir->uid = (*i)->uid;
	dir->guid = (*i)->gid;
	dir->mtime = (*i)->time;
	dir->xattr = (*i)->xattr;
	dir->dirs = NULL;

	if ((*i)->data == 3)
		/*
		 * if the directory is empty, skip the unnecessary
		 * lookup_entry, this fixes the corner case with
		 * completely empty filesystems where lookup_entry correctly
		 * returning -1 is incorrectly treated as an error
		 */
		return dir;

	start = sBlk.s.directory_table_start + (*i)->start;
	offset = (*i)->offset;
	size = (*i)->data + bytes - 3;

	while(bytes < size) {			
		if(swap) {
			squashfs_dir_header_3 sdirh;
			res = read_directory_data(&sdirh, &start, &offset, sizeof(sdirh));
			if(res)
				SQUASHFS_SWAP_DIR_HEADER_3(&dirh, &sdirh);
		} else
			res = read_directory_data(&dirh, &start, &offset, sizeof(dirh));
	
		if(res == FALSE)
			goto corrupted;

		dir_count = dirh.count + 1;
		TRACE("squashfs_opendir: Read directory header @ byte position "
			"%d, %d directory entries\n", bytes, dir_count);
		bytes += sizeof(dirh);

		/* dir_count should never be larger than SQUASHFS_DIR_COUNT */
		if(dir_count > SQUASHFS_DIR_COUNT) {
			ERROR("File system corrupted: too many entries in directory\n");
			goto corrupted;
		}

		while(dir_count--) {
			if(swap) {
				squashfs_dir_entry_3 sdire;
				res = read_directory_data(&sdire, &start,
					&offset, sizeof(sdire));
				if(res)
					SQUASHFS_SWAP_DIR_ENTRY_3(dire, &sdire);
			} else
				res = read_directory_data(dire, &start,
					&offset, sizeof(*dire));

			if(res == FALSE)
				goto corrupted;

			bytes += sizeof(*dire);

			/* size should never be SQUASHFS_NAME_LEN or larger */
			if(dire->size >= SQUASHFS_NAME_LEN) {
				ERROR("File system corrupted: filename too long\n");
				goto corrupted;
			}

			res = read_directory_data(dire->name, &start, &offset,
								dire->size + 1);

			if(res == FALSE)
				goto corrupted;

			dire->name[dire->size + 1] = '\0';

			/* check name for invalid characters (i.e /, ., ..) */
			if(check_name(dire->name, dire->size + 1) == FALSE) {
				ERROR("File system corrupted: invalid characters in name\n");
				goto corrupted;
			}

			TRACE("squashfs_opendir: directory entry %s, inode "
				"%d:%d, type %d\n", dire->name,
				dirh.start_block, dire->offset, dire->type);

			ent = malloc(sizeof(struct dir_ent));
			if(ent == NULL)
				MEM_ERROR();

			ent->name = strdup(dire->name);
			ent->start_block = dirh.start_block;
			ent->offset = dire->offset;
			ent->type = dire->type;
			ent->next = NULL;
			if(cur_ent == NULL)
				dir->dirs = ent;
			else
				cur_ent->next = ent;
			cur_ent = ent;
			dir->dir_count ++;
			bytes += dire->size + 1;
		}
	}

	/* check directory for duplicate names and sorting */
	if(check_directory(dir) == FALSE) {
		ERROR("File system corrupted: directory has duplicate names or is unsorted\n");
		goto corrupted;
	}

	return dir;

corrupted:
	squashfs_closedir(dir);
	return NULL;
}
```

---

## Pair 6: 210701 / 439495 (squashfs-tools, CVE-2021-40153)

- **Project**: squashfs-tools (https://github.com/plougher/squashfs-tools)
- **CVE / CWE**:CVE-2021-40153 / CWE-22
- **Fix commit**:79b5a555058eef4e1e7ff220c344d39f8cd09646(identical in both V/S rows)

**Pairing failure cause**: A cross-file twin mismatch of the same type as Pair 5, only running in the opposite direction: the V side (210701) verbatim-matches **the pre-fix version in unsquash-3.c** (and it is the only match; the code uses the `squashfs_dir_header_3`/`squashfs_dir_entry_3` structures, the empty-directory test `(*i)->data == 3`, and a size formula with `- 3` -- all traits unique to the v3 generation), while the S side (439495) verbatim-matches **the post-fix version in unsquash-1.c and unsquash-2.c** (structures without `_3`, the test `(*i)->data == 0`, a formula without `- 3`; the function is verbatim identical in those two files, so they are not distinguished) -- the two are two disk-format generations apart, so this is not the fixed version of V. Fix commit 79b5a555058e (the first-round fix for the CVE-2021-40153 "write escaping outside the target directory") likewise changed all four files together, each getting a `check_name` filename-validity check; `check_name` is present in the S-side code (that belongs to the fix of unsquash-1.c/unsquash-2.c), whereas the V side comes from unsquash-3.c, whose own fixed version should carry the same check as well -- but this is not that copy. The row idx=439495 likewise appears twice in the dataset as a verbatim copy: its rightful owner is the 210700 pair (its V matches the pre-fix version of unsquash-1.c/2.c, exactly the pre- and post-fix counterpart of 439495 within the same file -- a true pair); in the present pair it is a duplicated copy serving as filler.

- **Correct partner should be**: the post-fix version of `squashfs_opendir` from unsquash-3.c -- it exists upstream but was not extracted into the dataset.
- **Upstream forensics**: commit 79b5a555058e; the full pre/post texts of the four files were verbatim-matched against the dataset rows (the function is verbatim identical in unsquash-1.c and unsquash-2.c, and the two are not distinguished).

### V-side original text (idx=210701 in the dataset, target=1, vulnerable version, 117 lines)

```c
static struct dir *squashfs_opendir(unsigned int block_start, unsigned int offset,
	struct inode **i)
{
	squashfs_dir_header_3 dirh;
	char buffer[sizeof(squashfs_dir_entry_3) + SQUASHFS_NAME_LEN + 1]
		__attribute__((aligned));
	squashfs_dir_entry_3 *dire = (squashfs_dir_entry_3 *) buffer;
	long long start;
	int bytes;
	int dir_count, size;
	struct dir_ent *new_dir;
	struct dir *dir;

	TRACE("squashfs_opendir: inode start block %d, offset %d\n",
		block_start, offset);

	*i = read_inode(block_start, offset);

	dir = malloc(sizeof(struct dir));
	if(dir == NULL)
		EXIT_UNSQUASH("squashfs_opendir: malloc failed!\n");

	dir->dir_count = 0;
	dir->cur_entry = 0;
	dir->mode = (*i)->mode;
	dir->uid = (*i)->uid;
	dir->guid = (*i)->gid;
	dir->mtime = (*i)->time;
	dir->xattr = (*i)->xattr;
	dir->dirs = NULL;

	if ((*i)->data == 3)
		/*
		 * if the directory is empty, skip the unnecessary
		 * lookup_entry, this fixes the corner case with
		 * completely empty filesystems where lookup_entry correctly
		 * returning -1 is incorrectly treated as an error
		 */
		return dir;

	start = sBlk.s.directory_table_start + (*i)->start;
	bytes = lookup_entry(directory_table_hash, start);

	if(bytes == -1)
		EXIT_UNSQUASH("squashfs_opendir: directory block %d not "
			"found!\n", block_start);

	bytes += (*i)->offset;
	size = (*i)->data + bytes - 3;

	while(bytes < size) {			
		if(swap) {
			squashfs_dir_header_3 sdirh;
			memcpy(&sdirh, directory_table + bytes, sizeof(sdirh));
			SQUASHFS_SWAP_DIR_HEADER_3(&dirh, &sdirh);
		} else
			memcpy(&dirh, directory_table + bytes, sizeof(dirh));
	
		dir_count = dirh.count + 1;
		TRACE("squashfs_opendir: Read directory header @ byte position "
			"%d, %d directory entries\n", bytes, dir_count);
		bytes += sizeof(dirh);

		/* dir_count should never be larger than SQUASHFS_DIR_COUNT */
		if(dir_count > SQUASHFS_DIR_COUNT) {
			ERROR("File system corrupted: too many entries in directory\n");
			goto corrupted;
		}

		while(dir_count--) {
			if(swap) {
				squashfs_dir_entry_3 sdire;
				memcpy(&sdire, directory_table + bytes,
					sizeof(sdire));
				SQUASHFS_SWAP_DIR_ENTRY_3(dire, &sdire);
			} else
				memcpy(dire, directory_table + bytes,
					sizeof(*dire));
			bytes += sizeof(*dire);

			/* size should never be SQUASHFS_NAME_LEN or larger */
			if(dire->size >= SQUASHFS_NAME_LEN) {
				ERROR("File system corrupted: filename too long\n");
				goto corrupted;
			}

			memcpy(dire->name, directory_table + bytes,
				dire->size + 1);
			dire->name[dire->size + 1] = '\0';
			TRACE("squashfs_opendir: directory entry %s, inode "
				"%d:%d, type %d\n", dire->name,
				dirh.start_block, dire->offset, dire->type);
			if((dir->dir_count % DIR_ENT_SIZE) == 0) {
				new_dir = realloc(dir->dirs, (dir->dir_count +
					DIR_ENT_SIZE) * sizeof(struct dir_ent));
				if(new_dir == NULL)
					EXIT_UNSQUASH("squashfs_opendir: "
						"realloc failed!\n");
				dir->dirs = new_dir;
			}
			strcpy(dir->dirs[dir->dir_count].name, dire->name);
			dir->dirs[dir->dir_count].start_block =
				dirh.start_block;
			dir->dirs[dir->dir_count].offset = dire->offset;
			dir->dirs[dir->dir_count].type = dire->type;
			dir->dir_count ++;
			bytes += dire->size + 1;
		}
	}

	return dir;

corrupted:
	free(dir->dirs);
	free(dir);
	return NULL;
}
```

### S-side original text (idx=439495 in the dataset, target=0, mispaired "fixed version", 123 lines)

```c
static struct dir *squashfs_opendir(unsigned int block_start, unsigned int offset,
	struct inode **i)
{
	squashfs_dir_header_2 dirh;
	char buffer[sizeof(squashfs_dir_entry_2) + SQUASHFS_NAME_LEN + 1]
		__attribute__((aligned));
	squashfs_dir_entry_2 *dire = (squashfs_dir_entry_2 *) buffer;
	long long start;
	int bytes;
	int dir_count, size;
	struct dir_ent *new_dir;
	struct dir *dir;

	TRACE("squashfs_opendir: inode start block %d, offset %d\n",
		block_start, offset);

	*i = read_inode(block_start, offset);

	dir = malloc(sizeof(struct dir));
	if(dir == NULL)
		EXIT_UNSQUASH("squashfs_opendir: malloc failed!\n");

	dir->dir_count = 0;
	dir->cur_entry = 0;
	dir->mode = (*i)->mode;
	dir->uid = (*i)->uid;
	dir->guid = (*i)->gid;
	dir->mtime = (*i)->time;
	dir->xattr = (*i)->xattr;
	dir->dirs = NULL;

	if ((*i)->data == 0)
		/*
		 * if the directory is empty, skip the unnecessary
		 * lookup_entry, this fixes the corner case with
		 * completely empty filesystems where lookup_entry correctly
		 * returning -1 is incorrectly treated as an error
		 */
		return dir;
		
	start = sBlk.s.directory_table_start + (*i)->start;
	bytes = lookup_entry(directory_table_hash, start);
	if(bytes == -1)
		EXIT_UNSQUASH("squashfs_opendir: directory block %d not "
			"found!\n", block_start);

	bytes += (*i)->offset;
	size = (*i)->data + bytes;

	while(bytes < size) {			
		if(swap) {
			squashfs_dir_header_2 sdirh;
			memcpy(&sdirh, directory_table + bytes, sizeof(sdirh));
			SQUASHFS_SWAP_DIR_HEADER_2(&dirh, &sdirh);
		} else
			memcpy(&dirh, directory_table + bytes, sizeof(dirh));
	
		dir_count = dirh.count + 1;
		TRACE("squashfs_opendir: Read directory header @ byte position "
			"%d, %d directory entries\n", bytes, dir_count);
		bytes += sizeof(dirh);

		/* dir_count should never be larger than SQUASHFS_DIR_COUNT */
		if(dir_count > SQUASHFS_DIR_COUNT) {
			ERROR("File system corrupted: too many entries in directory\n");
			goto corrupted;
		}

		while(dir_count--) {
			if(swap) {
				squashfs_dir_entry_2 sdire;
				memcpy(&sdire, directory_table + bytes,
					sizeof(sdire));
				SQUASHFS_SWAP_DIR_ENTRY_2(dire, &sdire);
			} else
				memcpy(dire, directory_table + bytes,
					sizeof(*dire));
			bytes += sizeof(*dire);

			/* size should never be SQUASHFS_NAME_LEN or larger */
			if(dire->size >= SQUASHFS_NAME_LEN) {
				ERROR("File system corrupted: filename too long\n");
				goto corrupted;
			}

			memcpy(dire->name, directory_table + bytes,
				dire->size + 1);
			dire->name[dire->size + 1] = '\0';

			/* check name for invalid characters (i.e /, ., ..) */
			if(check_name(dire->name, dire->size + 1) == FALSE) {
				ERROR("File system corrupted: invalid characters in name\n");
				goto corrupted;
			}

			TRACE("squashfs_opendir: directory entry %s, inode "
				"%d:%d, type %d\n", dire->name,
				dirh.start_block, dire->offset, dire->type);
			if((dir->dir_count % DIR_ENT_SIZE) == 0) {
				new_dir = realloc(dir->dirs, (dir->dir_count +
					DIR_ENT_SIZE) * sizeof(struct dir_ent));
				if(new_dir == NULL)
					EXIT_UNSQUASH("squashfs_opendir: "
						"realloc failed!\n");
				dir->dirs = new_dir;
			}
			strcpy(dir->dirs[dir->dir_count].name, dire->name);
			dir->dirs[dir->dir_count].start_block =
				dirh.start_block;
			dir->dirs[dir->dir_count].offset = dire->offset;
			dir->dirs[dir->dir_count].type = dire->type;
			dir->dir_count ++;
			bytes += dire->size + 1;
		}
	}

	return dir;

corrupted:
	free(dir->dirs);
	free(dir);
	return NULL;
}
```
