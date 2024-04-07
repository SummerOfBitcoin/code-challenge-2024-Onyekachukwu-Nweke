package utils

func parseTransactions(dir string) ([]Transaction, error) {
	var transactions []Transaction

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			var tx Transaction
			err = json.Unmarshal(data, &tx)
			if err != nil {
				return err
			}

			transactions = append(transactions, tx)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return transactions, nil
}