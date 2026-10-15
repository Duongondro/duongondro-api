package atrest

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Reseal rewrites every sealed value not under the current key, and recomputes the
// blind indexes of its row, which the new key changes too. It is the second half of
// a key rotation: with SECRET_KEY_BASE set to the new key and SECRET_KEY_BASE_PREVIOUS
// to the old one, `server migrate` runs it before the service starts, so the server
// never looks a value up by a hash under the old key. Once it has run, the previous
// key can go. Each table is one transaction; running it again does nothing.
func Reseal(ctx context.Context, pool *pgxpool.Pool, k *Keys) (int, error) {
	total := 0
	for _, t := range Tables {
		n, err := resealTable(ctx, pool, k, t)
		if err != nil {
			return total, fmt.Errorf("resealing %s: %w", t.Name, err)
		}
		total += n
	}
	return total, nil
}

func resealTable(ctx context.Context, pool *pgxpool.Pool, k *Keys, t Table) (int, error) {
	n := 0
	err := pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		types, err := columnTypes(ctx, tx, t.Name)
		if err != nil {
			return err
		}
		// Every key column as bytes, as Row takes them, then the sealed values.
		var sel []string
		for _, c := range t.Key {
			switch types[c] {
			case "uuid":
				sel = append(sel, fmt.Sprintf("uuid_send(%s)", quote(c)))
			case "text":
				sel = append(sel, fmt.Sprintf("convert_to(%s, 'UTF8')", quote(c)))
			case "bytea":
				sel = append(sel, quote(c))
			default:
				return fmt.Errorf("key column %s.%s has type %q", t.Name, c, types[c])
			}
		}
		for _, c := range t.Sealed {
			sel = append(sel, quote(c.Name))
		}
		rows, err := tx.Query(ctx, fmt.Sprintf("SELECT %s FROM %s FOR UPDATE", strings.Join(sel, ", "), quote(t.Name)))
		if err != nil {
			return err
		}
		type stored struct{ key, sealed [][]byte }
		var all []stored
		for rows.Next() {
			vals := make([][]byte, len(sel))
			ptrs := make([]any, len(sel))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				return err
			}
			all = append(all, stored{key: vals[:len(t.Key)], sealed: vals[len(t.Key):]})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range all {
			if allCurrent(k, r.sealed) {
				continue
			}
			if err := resealRow(ctx, tx, k, t, types, r.key, r.sealed); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

func allCurrent(k *Keys, sealed [][]byte) bool {
	for _, s := range sealed {
		if s != nil && !k.Current(s) {
			return false
		}
	}
	return true
}

func resealRow(ctx context.Context, tx pgx.Tx, k *Keys, t Table, types map[string]string, key, sealed [][]byte) error {
	oldRow := RowOf(key...)
	plain := make([][]byte, len(t.Sealed))
	for i, c := range t.Sealed {
		p, err := k.OpenBytes(c, oldRow, sealed[i])
		if err != nil {
			return err
		}
		plain[i] = p
	}
	// New blind indexes from the plaintext; a key column that is one of them changes.
	newKey := append([][]byte(nil), key...)
	var set []string
	var args []any
	for _, ix := range t.Indexes {
		var h []byte
		for i, c := range t.Sealed {
			if c == ix.Of && sealed[i] != nil {
				h = k.Hash(plain[i]) // stored normalised; hashed as stored
			}
		}
		args = append(args, h)
		set = append(set, fmt.Sprintf("%s = $%d", quote(ix.Column.Name), len(args)))
		for j, c := range t.Key {
			if c == ix.Column.Name {
				newKey[j] = h
			}
		}
	}
	newRow := RowOf(newKey...)
	for i, c := range t.Sealed {
		var v []byte
		if sealed[i] != nil {
			v = k.Seal(c, newRow, plain[i])
		}
		args = append(args, v)
		set = append(set, fmt.Sprintf("%s = $%d", quote(c.Name), len(args)))
	}
	var where []string
	for j, c := range t.Key {
		expr := quote(c)
		switch types[c] {
		case "uuid":
			expr = fmt.Sprintf("uuid_send(%s)", expr)
		case "text":
			expr = fmt.Sprintf("convert_to(%s, 'UTF8')", expr)
		}
		args = append(args, key[j])
		where = append(where, fmt.Sprintf("%s = $%d", expr, len(args)))
	}
	tag, err := tx.Exec(ctx, fmt.Sprintf("UPDATE %s SET %s WHERE %s", quote(t.Name), strings.Join(set, ", "),
		strings.Join(where, " AND ")), args...)
	if err == nil && tag.RowsAffected() != 1 {
		err = fmt.Errorf("updated %d rows, want 1", tag.RowsAffected())
	}
	return err
}

func columnTypes(ctx context.Context, tx pgx.Tx, table string) (map[string]string, error) {
	rows, err := tx.Query(ctx, `SELECT column_name, data_type FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = $1`, table)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			rows.Close()
			return nil, err
		}
		out[name] = typ
	}
	rows.Close()
	return out, rows.Err()
}

func quote(ident string) string { return pgx.Identifier{ident}.Sanitize() }
