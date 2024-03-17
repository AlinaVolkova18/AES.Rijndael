using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rijndael
{
	public class Block
	{

		public Block(int size)
		{
			_bytes = new Byte[4, size];
		}


		public Byte[,] Bytes => _bytes;
		public int Rows => 4;
		public int Columns => _bytes.GetLength(1);


		private Byte[,] _bytes;


		public void ShiftRowToLeft(int rowIndex, int shiftValue)
		{
			for (int i = 0; i < shiftValue; i++)
				ShiftRowToLeft(rowIndex);
		}

		private void ShiftRowToLeft(int rowIndex)
		{
			Byte tempValue = _bytes[rowIndex, 0];

			for (int i = 0; i < Columns - 1; i++)
				_bytes[rowIndex, i] = _bytes[rowIndex, i + 1];

			_bytes[rowIndex, Columns - 1] = tempValue;
		}


		public override string ToString()
		{
			StringBuilder stringBuilder = new StringBuilder();

			for (int i = 0; i < Rows; i++)
			{
				for (int j = 0; j < Columns; j++)
					stringBuilder.Append(_bytes[i, j].ToString("X16") + " ");

				stringBuilder.AppendLine();
			}

			return stringBuilder.ToString();
		}
	}
}
