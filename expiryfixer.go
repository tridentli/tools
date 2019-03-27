package main

// PGP Signatures do not expire, the keys they sign do, based on the difference between key creation and the signatures key-lifetime.
// This corrects that difference in the Trident database.
// Just a temporary fix till things are back on track... (last words).

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	pf "trident.li/pitchfork/lib"
)

// GetKeyInfo fetches the key_id and expiration time
//
// This might fail, errors seen:
// 73  Key for identity not found
//     => well, that one is explainable :)
//  2  illegal base64 data at input byte 0
// 11  openpgp: invalid argument: no armored data found
// 21  openpgp: invalid data: first packet was not a public/private key
//  3  openpgp: invalid data: signature packet found before user id packet
//  2  openpgp: invalid data: subkey packet not followed by signature
//  1  openpgp: invalid data: subkey signature invalid: openpgp: invalid data: signing subkey is missing cross-signature
// 17  openpgp: invalid data: user ID packet not followed by self-signature
//  5  openpgp: invalid data: user ID self-signature invalid: openpgp: invalid signature: hash tag doesn't match
//  1  openpgp: unsupported feature: large public exponent
//  4  openpgp: unsupported feature: public key algorithm 100
//  1  openpgp: unsupported feature: public key type: 22
//  1  openpgp: unsupported feature: unknown critical signature subpacket type 26
//     => SIGSUBPKT_POLICY (https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=common/openpgpdefs.h ~L112)
//  2  openpgp: unsupported feature: unknown critical signature subpacket type 6
//     => SIGSUBPKT_REGEXP
func GetKeyInfo(keyring string, email string) (key_id string, key_exp time.Time, err error) {
	// Lower it, just in case
	email = strings.ToLower(email)

	// Parse the Keyring
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(keyring))
	if err != nil {
		return
	}

	ids := 0

	// Find the right entity
	for _, e := range entities {
		for _, i := range e.Identities {
			ids++
			// Some people do camelcase in their email....
			em := strings.ToLower(i.UserId.Email)

			// The identity we are looking for?
			if em == email {
				// Format the Key ID, 16 bytes, prefixed with zeros where needed
				key_id = strings.ToUpper(fmt.Sprintf("%016x", e.PrimaryKey.KeyId))

				// Get expiration date
				sig := i.SelfSignature
				if sig.KeyLifetimeSecs == nil {
					key_exp = time.Unix(0, 0)
				} else {
					key_exp = e.PrimaryKey.CreationTime.Add(time.Duration(*sig.KeyLifetimeSecs) * time.Second)
				}

				return
			}
		}
	}

	err = errors.New("Key for identity not found")

	if ids != 0 {
		fmt.Printf("%s Identities: ", email)
		for _, e := range entities {
			for _, i := range e.Identities {
				fmt.Printf("%s ", i.UserId.Email)
			}
		}
		fmt.Printf("\n")
	} else {
		fmt.Printf("%s No Identities: ", email)
	}

	return
}

func main() {
	// As per default we want it to just check for problems
	// if one really wants to execute this, then you need to give the option
	apply := false

	// Limit for quick runs
	limit := 0

	// Normally we only check keys without expiry date
	allkeys := false

	// A specific user to fix
	fixident := ""

	// Verbosity
	verbose := false

	flag.BoolVar(&apply, "apply", false, "Actually perform changes (default: false)")
	flag.IntVar(&limit, "limit", 0, "Limit to X keys, for quicker checks (default: 0 / unlimited)")
	flag.BoolVar(&allkeys, "allkeys", false, "Run over all keys, not only keys with a 1970-01-01 expiry date (default: false)")
	flag.StringVar(&fixident, "ident", "", "Specific user to fix (default: all users with a key")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output? (default: false)")
	flag.Parse()

	// Setup pitchfork, load DB details etc
	err := pf.Setup("trident", "", false, 0)
	if err != nil {
		return
	}

	// XXX: Happily ignore SQL injection by concatting strings from user input...
	q := "SELECT member, email, pgpkey_id, keyring, pgpkey_expire " +
		"FROM member_email " +
		"WHERE keyring != '' "

	if !allkeys {
		q += "AND pgpkey_expire = '1970-01-01 00:00:00' "
	}

	if fixident != "" {
		q += "AND member = '" + fixident + "'"
	}

	q += "ORDER BY member, email"

	if limit != 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := pf.DB.Query(q)
	if err != nil {
		err = errors.New("Could not retrieve emails for user")
		return
	}

	defer rows.Close()

	lineit := false

	for rows.Next() {
		var member string
		var email string
		var pgpkey_id string
		var keyring string
		var old_exp time.Time

		if lineit {
			fmt.Printf("---------------\n")
		}

		// Unless we succeed lineit will be true and an error will have been printed out
		lineit = true

		err = rows.Scan(&member, &email, &pgpkey_id, &keyring, &old_exp)
		if err != nil {
			fmt.Printf("Member %s, Email %s, Key %s failed to Scan: %s\n", member, email, pgpkey_id, err.Error())
			continue
		}

		if verbose {
			fmt.Printf("member: %s <%s>, key: %s\n", member, email, pgpkey_id)
		}

		key_id, key_exp, err := GetKeyInfo(keyring, email)
		if err != nil {
			fmt.Printf("Member %s, Email %s, Key %s failed to get KeyInfo: %s\n", member, email, pgpkey_id, err.Error())
			continue
		}

		if key_id == "" {
			fmt.Printf("Member %s, Email %s, Key %s failed to get KeyInfo: KEY MISSING\n", member, email, pgpkey_id, err.Error())
			continue
		}

		if key_id != pgpkey_id {
			// Might be the longer key format
			up_pgpkey_id := strings.ToUpper(pgpkey_id)
			if len(pgpkey_id) == 8 && key_id[8:] == up_pgpkey_id {
				// Yep, longer variant of key, just update the key_id
			} else if key_id[16-len(pgpkey_id):] == up_pgpkey_id {
				// Yep, longer variant of key, just update the key_id
			} else {
				// Something else, complain, but update it, as that fixes the problem
				fmt.Printf("Member %s, Email %s, Key %s, apparently now is keyid %s / %s instead?\n", member, email, pgpkey_id, key_id, key_id[8:])
				//continue
			}
		}

		// No changes?
		if old_exp.Unix() == key_exp.Unix() && pgpkey_id == key_id {
			continue
		}

		if verbose {
			fmt.Printf("  Old Expiry: %s (%d)\n", old_exp, old_exp.Unix())
			fmt.Printf("  New Expiry: %s (%d)\n", key_exp, key_exp.Unix())
		}

		if apply {
			q = "UPDATE member_email " +
				"SET pgpkey_expire = $1, " +
				"pgpkey_id = $2 " +
				"WHERE member = $3 AND " +
				"email = $4 AND " +
				"pgpkey_id = $5 "
			err = pf.DB.Exec(nil, "Fixup PGP Key Expiry/ID", 1, q, key_exp, key_id, member, email, pgpkey_id)

			// Notice when changing keyid
			if verbose {
				fmt.Printf("  pgpkey_id = %s => %s :: %s\n", pgpkey_id, key_id, key_exp)
			}

			if err != nil {
				fmt.Printf("Member %s, Email %s, Key %s/%s failed to update expiry to %s: %s\n", member, email, pgpkey_id, key_id, key_exp, err.Error())
				break
			}
		}

		lineit = false

		// Long piece of code abose, thus clearly show that we loop here
		continue
	}

	return
}
